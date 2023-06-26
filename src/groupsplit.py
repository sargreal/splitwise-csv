import multiprocessing
import os
import re
import csv
import sys
import json
import pickle
import pprint
import urllib
import hashlib
import logging
import argparse
import requests
import subprocess
import webbrowser
import oauthlib.oauth1
from money import Money
from pprint import pprint
from datetime import datetime
from tabulate import tabulate
from splitwise import Splitwise, Expense, user, group
from server import oauth_server

LOGGING_DISABELED = 100
log_levels = [LOGGING_DISABELED, logging.CRITICAL, logging.ERROR,
              logging.WARNING, logging.INFO, logging.DEBUG]
# Adapted from:
# https://docs.python.org/2/howto/logging.html#configuring-logging
# create logger
logger = logging.getLogger(__name__)

# create console handler and set level to debug
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)

# create formatter
formatter = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# add formatter to ch
ch.setFormatter(formatter)

# add ch to logger
logger.addHandler(ch)
logging.basicConfig(format='%(asctime)s %(message)s',
                    datefmt='%m/%d/%Y %I:%M:%S %p')


def split(total, num_people):
    """
    Splits a total to the nearest whole cent and remainder
    Total is a Money() type so no need to worry about floating point errors
    return (2-tuple): base amount owed, remainder of cents which couldn't be evenly split

    Example: >>> split(1.00, 6) 
    (0.16, 0.04)
    """
    base = total * 100 // num_people / 100
    extra = total - num_people * base
    assert base * num_people + extra == total, "InternalError:" + \
        " something doesnt add up here: %d * %d + %d != %d" % (
            base, num_people, extra, total)
    return base, extra


def do_hash(msg: str):
    m = hashlib.md5()
    m.update(msg.encode('utf-8'))
    return m.hexdigest()


class SplitwiseImport:
    """
    Client for communicating with Splitwise api
    """

    def __init__(self, access_token_file='access_token.json'):
        self.get_client_auth()
        self.access_token_file = access_token_file
        self.splitwise = Splitwise(self.ckey, self.csecret)
        if os.path.isfile(access_token_file):
            with open(access_token_file, 'r') as tokenFile:
                token = json.load(tokenFile)
                self.splitwise.setOAuth2AccessToken(token)
        else:
            self.authorize()

    def get_client_auth(self):
        if os.path.isfile("consumer_oauth.json"):
            with open("consumer_oauth.json", 'rb') as oauth_file:
                consumer = json.load(oauth_file)
                ckey = consumer['consumer_key']
                csecret = consumer['consumer_secret']
        else:
            with open("consumer_oauth.json", 'w') as oauth_file:
                json.dump({'consumer_key': 'YOUR KEY HERE',
                           'consumer_secret': 'YOUR SECRET HERE'}, oauth_file)
            exit("go to https://secure.splitwise.com/oauth_clients to obtain your keys." +
                 "place them in consumer_oauth.json")
        self.ckey = ckey
        self.csecret = csecret

    def authorize(self):

        url, state = self.splitwise.getOAuth2AuthorizeURL(
            "http://localhost:5000")
        print(state)

        queue = multiprocessing.Queue()
        p = multiprocessing.Process(target=oauth_server, args=(queue,))
        p.start()
        webbrowser.open_new(url)

        print("waiting for server to respond")
        result = queue.get(block=True, timeout=120)
        p.terminate()

        print(result)
        assert result["state"] == state
        access_token = self.splitwise.getOAuth2AccessToken(
            result["code"], "http://localhost:5000")
        print(access_token)
        with open(self.access_token_file, 'w') as token:
            json.dump(access_token, token)
        self.splitwise.setOAuth2AccessToken(access_token)

    def splitwise_api(self):
        return self.splitwise

    def get_id(self):
        return self.splitwise.getCurrentUser().id

    def get_groups(self) -> list[group.Group]:
        return self.splitwise.getGroups()

    # def post_expense(self, uri):

    #     resp = self.api_call(uri, 'POST')
    #     if resp["errors"]:
    #         sys.stderr.write("URI:")
    #         sys.stderr.write(uri)
    #         pprint(resp, stream=sys.stderr)
    #     else:
    #         sys.stdout.write(".")
    #         sys.stdout.flush()

    def delete_expense(self, expense_id):
        return self.splitwise.deleteExpense(expense_id)

    def get_expenses(self, after_date="", limit=0, allow_deleted=True) -> list[Expense]:
        expenses = self.splitwise.getExpenses(
            updated_after=after_date, limit=limit)
        if not allow_deleted:
            expenses = [exp for exp in expenses
                        if exp.deleted_at is None]
        return expenses


def get_input_int(prompt: str) -> int:
    try:
        return int(input(prompt))
    except ValueError as e:
        print(e)
        print("Please enter a number")
        return get_input_int(prompt)


def get_input_yn(prompt: str) -> int:
    try:
        result = input(prompt + " [Y/n] ")
        if result.lower() == 'y':
            return True
        elif result.lower() == 'n':
            return False
        raise ValueError("Please enter y or n")
    except ValueError as e:
        print(e)
        return get_input_yn(prompt)


def get_input_currency(prompt: str) -> str:
    try:
        result = input(prompt).upper()
        Money("1.00", result)  # pylint: disable=W0612
        return result
    except ValueError as e:
        print(e)
        return get_input_currency(prompt)


class CsvSettings():
    def __init__(self, rows, members: dict[int, user.Friend]):
        print("These are the first two rows of your csv")
        print('\n'.join([str(t) for t in rows[0:2]]))
        print('Colnum numbers start at 0')
        self.date_col = get_input_int("Which column has the date? ")
        self.amount_col = get_input_int("Which column has the amount? ")
        self.desc_col = get_input_int("Which column has the description? ")
        self.paid_by_settings = {}
        for member in members.values():
            print(
                f"Member settings for {str(member.first_name)} {str(member.last_name)}")
            member_paid_column = get_input_int(
                f"What is the column that states how much they paid? ")
            member_impacted_column = get_input_int(
                f"What is the column that states how much was impacted? ")
            self.paid_by_settings[member.id] = {
                "paid_column": member_paid_column,
                "impacted_column": member_impacted_column
            }
        self.has_title_row = get_input_yn("Does first row have titles? ")
        self.newest_transaction = ''
        self.local_currency = get_input_currency(
            "What currency were these transactions made in? ")
        self.remember = get_input_yn("Remember these settings? ")

    def __del__(self):
        if self.remember:
            with open("csv_settings.pkl", "wb") as pkl:
                pickle.dump(self, pkl)

    def record_newest_transaction(self, rows):
        if self.has_title_row:
            self.newest_transaction = do_hash(str(rows[1]))
        else:
            self.newest_transaction = do_hash(str(rows[0]))


class SplitGenerator():
    def __init__(self, options, api: SplitwiseImport):
        csv_file = options.csv_file
        group_name = options.group_name
        self.api = api
        self.options = options
        self.get_group(group_name)
        with open(csv_file, 'r') as csvfile:
            reader = csv.reader(csvfile)
            self.rows = [x for x in reader]

        if os.path.isfile(options.csv_settings):
            with open(options.csv_settings, 'rb') as f:
                self.csv = pickle.load(f)
        else:
            self.csv = CsvSettings(self.rows, self.members)

        if self.csv.has_title_row:
            self.rows = self.rows[1:]

        self.make_transactions()
        self.csv.record_newest_transaction(self.rows)
        self.splits = []
        self.ask_for_splits()

    def make_transactions(self):
        """
        Consume the row data from the csv file into a format which is easy to upload to splitwise
        Filter out all deposits (positive amounts)
        **change csvDateFormat to the format in your csv if necessary** 
        Further reading on date formats: https://docs.python.org/2/library/datetime.html#strftime-and-strptime-behavior
        """
        csvDateFormat = "%d/%m/%Y %H:%M"
        self.transactions = []
        for r in self.rows:
            if not self.options.try_all and do_hash(str(r)) == self.csv.newest_transaction:
                print("Found newest transaction, stopping")
                break
            if float(r[self.csv.amount_col]) > 0:
                print("adding row: " + str(r))
                transaction = {
                    "date": datetime.strftime(datetime.strptime(r[self.csv.date_col], csvDateFormat), "%Y-%m-%dT%H:%M:%SZ"),
                    "amount": Money(r[self.csv.amount_col], self.csv.local_currency),
                    "desc": re.sub('\s+', ' ', r[self.csv.desc_col]),
                }
                for member in self.members.values():
                    transaction[member.id] = {
                        "paid_share": Money(r[self.csv.paid_by_settings[member.id]["paid_column"]], self.csv.local_currency),
                        "owed_share": - 1 * Money(r[self.csv.paid_by_settings[member.id]["impacted_column"]], self.csv.local_currency),
                    }
                self.transactions.append(transaction)

    def get_group(self, name):
        """
        Wrapper around splitwise api for retreiving groups
        by name. Handles error cases: multiple groups with same name, 
        no group found, group has no members.

        name: the name of your Splitwise group (case insensitive)
        """
        num_found = 0
        gid = ''
        members = {}
        groups = self.api.get_groups()
        for group in groups:
            if group.name.lower() == name.lower():
                gid = group.id
                members = {m.id: m for m in group.members}
                num_found += 1

        if num_found > 1:
            exit("More than 1 group found with name:" + name)
        elif num_found < 1:
            exit("No matching group with name:" + name)
        elif len(members) < 1:
            exit("No members in group with name:" + name)

        self.members = members
        self.gid = gid

    def get_member_list(self) -> list[user.Friend]:
        return list(self.members.values())

    def ask_for_splits(self):
        """
        Ask the user whether they would like to split a given expense and if so
        add it to tee list of transactions to upload to Splitwise. Gets final
        confirmation before returning.
        """
        print("Found {0} transactions".format(len(self.transactions)))
        i = 0
        for t in self.transactions:
            if self.options.yes or input("%d: %s at %s $%s. Split? [y/N]" % (i, t['date'], t['desc'], t['amount'])).lower() == 'y':
                self.splits.append(t)

        print("-" * 40)
        print("Your Chosen Splits")
        print("-" * 40)
        headers = {"date": "Date", "amount": "Amount", "desc": "Description"}
        headers.update({m.id: m.first_name for m in self.members.values()})
        print(tabulate(self.splits, headers=headers))

        # Kill program if user doesn't want to submit splits
        assert self.options.yes or get_input_yn(
            "Confirm submission? "), "User canceled submission"

    def __getitem__(self, index):
        """
        Implement an iterator for SplitGenerator
        for every split in self.splits, emit the URI needed
        to upload that split to Splitwise
        """
        s = self.splits[index]
        # one_cent = Money("0.01", self.csv.local_currency)
        num_people = len(self.members) + 1
        # base, extra = split(s['amount'], num_people)
        expense = Expense()
        expense.setCost(s["amount"].amount)
        expense.setDescription(s["desc"])
        expense.setDate(s["date"])
        expense.setGroupId(self.gid)
        expense.setCurrencyCode(self.csv.local_currency)
        # payer = user.ExpenseUser()
        # payer.setId(self.api.get_id())
        # payer.setPaidShare(s["amount"].amount)
        # payer.setOwedShare(base.amount)
        # expense.addUser(payer)
        for member in self.members.values():
            expenseUser = user.ExpenseUser()
            expenseUser.setId(member.id)
            shares = s[member.id]
            expenseUser.setPaidShare(shares["paid_share"].amount)
            expenseUser.setOwedShare(shares["owed_share"].amount)
            expense.addUser(expenseUser)
        return expense


def main():
    usage = "groupsplit.py [options] <path to csv file> <splitwise group name>"
    parser = argparse.ArgumentParser(usage=usage)
    parser.add_argument('-v', '--verbosity', default=2, dest='verbosity',
                        help='change the logging level (0 - 6) default: 2')
    parser.add_argument('-y', '--yes', default=False, action='store_true', dest='yes',
                        help='split all transactions in csv without confirmation')
    parser.add_argument('-d', '--dryrun', default=False, action='store_true',
                        dest='dryrun', help='prints requests instead of sending them')
    parser.add_argument('--csv-settings', default='csv_settings.pkl', dest='csv_settings',
                        help='supply different csv_settings object (for testing mostly)')
    parser.add_argument('--access-token', default='access_token.json', dest='access_token',
                        help='supply different splitwise api client (for testing mostly)')
    parser.add_argument('-a', '--all', default=False, action='store_true', dest='try_all',
                        help='consider all transactions in csv file no matter whether they were already seen')
    parser.add_argument(
        'csv_file', help="Path to the csv file that is going to be imported")
    parser.add_argument('group_name', help="Name of the splitwise group")
    options = parser.parse_args()
    logger.setLevel(log_levels[options.verbosity])
    sp = SplitwiseImport(options.access_token)
    split_gen = SplitGenerator(options, sp)
    print("Uploading splits")
    for expense in split_gen:
        if options.dryrun:
            print(expense)
            continue
        sp.splitwise_api().createExpense(expense)
    sys.stdout.write("\n")
    sys.stdout.flush()


if __name__ == "__main__":
    main()

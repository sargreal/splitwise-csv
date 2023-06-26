import multiprocessing
from flask import Flask, request
import json


def oauth_server(queue: multiprocessing.Queue):
    app = Flask(__name__)

    @app.route('/')
    def authorize():
        queue.put({"redirect_uri": request.url,
                   "code": request.args["code"], "state": request.args["state"]})

        return "Thank you, you can close the tab"

    @app.route('/test')
    def test():
        return "Hello!"

    app.run('localhost', 5000)

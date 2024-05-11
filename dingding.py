#!/usr/bin/python
# -*- coding: utf-8 -*-
import requests
import json
import sys
import os

headers = {'Content-Type': 'application/json;charset=utf-8'}
api_url = "https://oapi.dingtalk.com/robot/send?access_token=889041f2851723e6ffe14667de202e034ce8d1e5ce8683ad576a482195310382"

def msg(text,subject):
    json_text= {
        "actionCard": {
            "title": subject,
            "text": text,
            "hideAvatar": "0",
            "btnOrientation": "0",
            "btns": [
                {
                    "title": subject[:12],
                    "actionURL": ""
                    }
                ]
            },
            "msgtype": "actionCard"
        }

    print(requests.post(api_url,json.dumps(json_text),headers=headers).content)

if __name__== '__main__':
    text = sys.argv[0]
    text = text.replace("\n", "\n\n")
    subject = sys.argv[0]
    msg(text, subject)
# -*- coding: utf-8 -*-

from burp import IBurpExtender
from burp import IHttpListener

import re

class BurpExtender(IBurpExtender, IHttpListener):

    def registerExtenderCallbacks(self, callbacks):

        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Request and Response Modifier")
        callbacks.registerHttpListener(self)
        print("Loaded Request and Response Modifier!")
        return

    def processHttpMessage(self, toolFlag, messageIsRequest, currentRequest):

        requestinfo = self.helpers.analyzeRequest(currentRequest)
        requesturl  = requestinfo.getUrl()

        # if set to False all the domains will be affected
        onlyModifyInScopeDomains = True

        if onlyModifyInScopeDomains and not self.callbacks.isInScope(requesturl):
            return

        if messageIsRequest:
            request_bytes = currentRequest.getRequest()
            req_as_string = self.helpers.bytesToString(request_bytes)
            req_as_string = self.onRequest(req_as_string)
            request_bytes = self.helpers.stringToBytes(req_as_string)
            request_bytes = self.update_content_length(request_bytes, messageIsRequest)
            currentRequest.setRequest(request_bytes)
        else:
            response_bytes = currentRequest.getResponse()
            resp_as_string = self.helpers.bytesToString(response_bytes)
            resp_as_string = self.onResponse(resp_as_string)
            response_bytes = self.helpers.stringToBytes(resp_as_string)
            response_bytes = self.update_content_length(response_bytes, messageIsRequest)
            currentRequest.setResponse(response_bytes)

    def update_content_length(self, message_bytes, is_request):
        if is_request:
            message_info = self.helpers.analyzeRequest(message_bytes)
        else:
            message_info = self.helpers.analyzeResponse(message_bytes)

        content_length = len(message_bytes) - message_info.getBodyOffset()
        msg_as_string = self.helpers.bytesToString(message_bytes)
        msg_as_string = re.sub(
            r'Content-Length: \d+\r\n',
            r'Content-Length: {}\r\n'.format(content_length),
            msg_as_string,
            1
        )
        return self.helpers.stringToBytes(msg_as_string)

    def onRequest(self, request):
        # modify the request
        return request

    def onResponse(self, response):
        # modify the response
        return response

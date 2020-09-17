headers = dict({"Log-Identifier": "zap-active-scanner"});
def sendingRequest(msg, initiator, helper):
   for x in list(headers):
      msg.getRequestHeader().setHeader(x, headers[x]);
def responseReceived(msg, initiator, helper):
   pass;
from datetime import datetime, timezone

class EventReceiver:
    def __init__(self, trusted_issuers):
        self.trusted_issuers=set(trusted_issuers)
        self.seen=set()
        self.latest={}

    def accept(self,event):
        if event["iss"] not in self.trusted_issuers:
            return False,"UNTRUSTED_TRANSMITTER"
        if event["jti"] in self.seen:
            return False,"DUPLICATE"
        subject=event["subject"]
        ts=event["event_timestamp"]
        if subject in self.latest and ts < self.latest[subject]:
            return False,"STALE_OR_OUT_OF_ORDER"
        self.seen.add(event["jti"])
        self.latest[subject]=ts
        return True,"ACCEPTED"

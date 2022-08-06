from .DBConnector import DBConnector

class EventFactory:
    
    def __init__(self):
        pass
    
    def createEvent(self, eventDetailPacket):
        pass
    
    def getAllEventDetails(self, eventId):
        return None
    
    def getEventAuthor(self, eventId):
        return None
    
    def getEventDate(self, eventId):
        return None
    
    def eventRquiresLogin(self, eventId):
        return True
    
    def deleteEvent(self, eventId):
        pass
class UserRole():
    """
        @description:
        UserRole class defines the model for the various roles a registered user 
        can have. 
        Roles can be Chapter Leader, Maker, Requestor, Educator or a
        Disability Professional. 
        These user roles distinguishes a given user, at a high level, on what they 
        might use the website for.
        Example: A user with the Maker role would be intersted in volunteering to
        build devices for anyone who requested it.
    """
    userIsChapterLeader: bool = False
    userIsMaker: bool = False
    userIsDesigner: bool = False
    userIsRequestor: bool = False # Requestors can also be any persons with disability.
    userIsEducator: bool = False
    userIsDesigner: bool = False
    userIsDisabilityProfessional: bool = False
        
    def setUserIsChapterLeader(self, userIsChapterLeader: bool):
        self.userIsChapterLeader = userIsChapterLeader
    
    def getUserIsChapterLeader(self) -> bool:
        return self.userIsChapterLeader
    
    def setUserIsMaker(self, userIsMaker: bool):
        self.userIsMaker = userIsMaker
        
    def getUserIsMaker(self) -> bool:
        return self.userIsMaker
    
    def setUserIsRequestor(self, userIsRequestor: bool):
        self.userIsRequestor = userIsRequestor
        
    def getUserIsRequestor(self) -> bool:
        return self.userIsRequestor

    def setUserIsEducator(self, userIsEducator: bool):
        self.userIsEducator = userIsEducator
        
    def getUserIsEducator(self) -> bool:
        return self.userIsEducator
    
    def setUserIsDisabilityProfessional(self, userIsDisabilityProfessional: bool):
        self.userIsDisabilityProfessional = userIsDisabilityProfessional
        
    def getUserIsDisabilityProfessional(self) -> bool:
        return self.userIsDisabilityProfessional
        
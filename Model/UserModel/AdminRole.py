class AdminRole():
    """
    @description: Admin class specific to staff titles.
    """
    userIsSuperUser: bool = False
    userIsDirector: bool = False
    userIsSupervisor: bool = False
    userIsEngineer: bool = False
    userIsRegionalCoordinator: bool = False
    userIsResearchStudent: bool = False
        
    def setUserIsSuperUser(self, userIsSuperUser: bool):
        self.userIsSuperUser = userIsSuperUser
    
    def getUserIsSuperUser(self) -> bool:
        return self.userIsSuperUser
    
    def setUserIsDirector(self, userIsDirector):
        self.userIsDirector = userIsDirector
    
    def getUserIsDirector(self) -> bool:
        return self.userIsDirector

    def setUserIsSupervisor(self, userIsSupervisor):
        self.userIsDirector = userIsSupervisor
    
    def getUserIsSupervisor(self) -> bool:
        return self.userIsSupervisor
    
    def setUserIsEngineer(self, userIsEngineer):
        self.userIsEngineer = userIsEngineer
        
    def getUserIsEngineer(self) -> bool:
        return self.userIsEngineer

    def setUserIsRegionalCoordinator(self, userIsRegionalCoordinator):
        self.userIsRegionalCoordinator = userIsRegionalCoordinator
        
    def getUserIsRegionalCoordinator(self) -> bool:
        return self.userIsRegionalCoordinator

    def setUserIsResearchStudent(self, userIsResearchStudent):
        self.userIsResearchStudent = userIsResearchStudent
    
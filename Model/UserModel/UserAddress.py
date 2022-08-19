from Model import UserModel

class UserAddress(UserModel.User):
    
    address: str = None
    city: str = None
    province_state: str = None
    country: str = None
    postal_zip: str = None
    
    def __init__(self, email: str):
        super().__init__(email)
    
    def setAddress(self, address: str):
        self.address = address
        
    def getAddress(self) -> str:
        return self.address
    
    def setCity(self, city: str):
        self.city = city
    
    def getCity(self) -> str:
        return self.city
    
    def setProvinceState(self, provinceState: str):
        self.province_state = provinceState
        
    def getProvinceState(self) -> str:
        return self.province_state
    
    def setCountry(self, country: str):
        self.country = country
        
    def getCountry(self) -> str:
        return self.country
    
    def setPostalZip(self, postalZip: str):
        self.postal_zip = postalZip
        
    def getPostalZip(self) -> str:
        return self.postal_zip
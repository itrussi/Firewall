import ast
import os
from numpy import mod
from functools import cache

BLANK = object()
DELETED = object()

class HashTable():

    __slots__ = "length", "values", "delete_counter"

    def __init__(self, capacity):
        self.length = capacity
        self.values = capacity * [BLANK]
        self.delete_counter = 0

    def len(self):
        return self.length

    @cache
    def get_hash_values(self, data):
        
        if data == "":
            return "Cannot insert nothing!"
    
        elif type(data) == str:
            index = 0
            hash_value = 0
            letters = [x for x in data]
            
            while index != len(letters):
                value = ord(letters[index])
                hash_value = hash_value + value
                index = index + 1
                    
            index = mod(hash_value, (self.len()))
                
        elif type(data) == int:
            index = mod(data, (self.len()))
    
        elif type(data) == float:
            index = mod(round(data), (self.len()))
    
        else:
            index = 0
            hash_value = 0
            product = data['Username']        
            letters = [x for x in product]
                
            while index != len(letters):
                value = ord(letters[index])
                hash_value = hash_value + value
                index = index + 1
    
            index = mod(hash_value, (self.len()))
    
        return index

    def data_verification(self, data):

        if data == "":
            return False

        if type(data) == dict:
            if data['Username'] == "":
                return False

        return True
                
    def insert(self, data):

        verify = self.data_verification(data)
        dictionary = {
            "Test": "Test"
        }

        if verify == True:
            index = 0

            if isinstance(data, type(dictionary)) == True:
                temp_data = str(data.get('Username'))

            elif isinstance(data, type(dictionary)) == False:
                temp_data = data
                
            index = self.get_hash_values(temp_data)
    
            self.values[index] = data
            return "Inserted successfully!"
        else:
            return "Data verification failed"

    def search(self, data):

        self.delete_counter = 0
        index = 0
        dictionary = {
            "Test": "Test"
        }

        verify = self.data_verification(data)

        if verify == True:

            if isinstance(data, type(dictionary)) == True:
                temp_data = str(data.get('Username'))

            elif isinstance(data, type(dictionary)) == False:
                temp_data = data
            
            index = self.get_hash_values(temp_data)
                
            while self.values[index] != BLANK:
                temp = self.values[index]
    
                if isinstance(temp, type(dictionary)) == True:
                    temp_dict = temp
                    if temp_dict['Username'] == data:
                        return temp
                        
                elif isinstance(temp, type(dictionary)) == False:
                    pass
    
                if temp == data:
                    return temp
    
                elif temp == DELETED:
                    index += 1
                    self.delete_counter = self.delete_counter + 1
    
                elif temp == dict:
                    index += 1

                else:
                    index += 1
    
            if self.delete_counter > 0:
                return "Data not found"
    
            elif self.delete_counter == 0:
                return "Data not found"

        else:
            return "Data verification failed"

    def delete(self, data):

        verify = self.data_verification(data)
        dictionary = {
            "Test": "Test"
        }

        if verify == True:

            if isinstance(data, type(dictionary)) == True:
                temp_data = str(data.get('Username'))

            elif isinstance(data, type(dictionary)) == False:
                temp_data = data
            
            index = self.get_hash_values(temp_data)
    
            while self.values[index] != BLANK:

                temp = self.values[index]
                
                if isinstance(temp, type(dictionary)) == True:
                    if temp['Username'] == data:
                        self.values[index] = DELETED
                        return "Dictionary deleted!"

                elif isinstance(temp, type(dictionary)) == False:
                    pass
                
                if self.values[index] == data:
                    self.values[index] = DELETED
                    return f"{data} deleted!"

                elif self.values[index] == dict:
                    index += 1
                
                else:
                    index = index + 1
    
            return f"{data} is not in the table and so can't be deleted!"

        else:
            return "Data verification failed"

    def append(self, data, product):
        self.delete(product)
        self.insert(data)
        
        return "Data Changed!"
import os


#os.environ['MY_SQL_USER'] = 'pranp'
#os.environ['MY_SQL_PASSWORD'] = 'abc@123'

for k, v in sorted(os.environ.items()):
    print(k+':', v)
print('\n')
# list elements in path environment variable
[print(item) for item in os.environ['PATH'].split(';')]
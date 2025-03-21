#!/bin/python3

# ==============================
# Python Syntax and Fundamentals
# ==============================

# Indentation in Python
# Python uses indentation instead of brackets {} to define blocks of code.
# Indentation must be consistent within the block.

# ✅ Correct Indentation:
def test():
    print("test")
    print("test")

# ❌ Incorrect Indentation:
# def test():
#     print("test")  # this indentation is correct  
#         print("test")  # this is incorrectly indented


# ======================
# Variables and Data Types
# ======================

# Variables store data in named locations.
# Variables are case-sensitive.
# Use '=' to assign values.

name = "Ellerion"
print(name)

# Checking the data type of a variable
print(type(name))  # Output: <class 'str'>

# ======================
# Numbers in Python
# ======================

t1_int = 1
t1_float = 1.0
t1_complex = 3.14j
t1_hex = 0xa  # Interpreted as hexadecimal (prints 10)
t1_octal = 0o10  # Interpreted as octal (prints 8)

# Absolute value
print(abs(-4))  # Output: 4

# Rounding numbers
print(round(8.4))  # Output: 8

# Converting numbers to binary or hexadecimal
print(bin(8))  # Output: 0b1000
print(hex(8))  # Output: 0x8


# ======================
# String Formatting
# ======================

# Defining Strings
string1 = "string"  # Double quotes
string2 = 'string'  # Single quotes

# Multiline string using triple quotes
multiline_string = """This
is
a
multiline string."""

# Escaping Characters
escape_string = "I\'m a string"  # Using \ to escape single quote
escape_string = "I'm a string"  # Alternative method without escaping

# Newline escape
new_line = "I'm gonna start a new line here\nI start a new line."

# Escaping backslashes
escape_escape = "Let's \\ escape"

# Escaping hex values
abc = "\x41 \x42 \x43"  # Outputs 'A B C'

# ======================
# String Operations
# ======================

# Repeating a string
ten_a = "a" * 10
print(len(ten_a))  # Output: 10

# Checking if a substring exists
string1 = "I'm a string"
print("string" in string1)  # Output: True
print("strings" in string1)  # Output: False

# Checking string starts or ends with a character
print(string1.startswith("I"))  # Output: True
print(string1.index("I"))  # Output: 0

# Changing case
print(string1.upper())  # Converts to uppercase
print(string1.lower())  # Converts to lowercase

# Removing whitespace
password = "        I'm a password with spaces               "
print(password.strip())  # Removes leading and trailing spaces

# Replacing characters
password = "testing!"
print(password.replace("!", "?"))  # Output: testing?

# Splitting a string
string2 = "I have a comma, and I won’t forget"
print(string2.split(","))

# ======================
# Casting & Formatting
# ======================

# Concatenation
print("I am " + "a string")

# Casting - Explicitly converting a datatype
print("String 2 is " + str(len(string2)) + " characters long")

# String formatting - Automatically converts types
print("String 2 is {} characters long".format(len(string2)))

# Using format syntax for multiple objects
print("string4 is {} {} {}".format(len(string2), 5.0, 0x12))

# Specifying order of items (index starts at 0)
print("string4 is {0} {2} {1}".format(len(string2), 5.0, 0x12))

# Using f-strings (modern and efficient)
print(f"String 2 is {len(string2)} characters long")

# Formatting data types with f-strings
length = len(string2)
print(f"string2 is {length:.2f} characters long.")  # Float with 2 decimals
print(f"string2 is {length:b} characters long.")  # Binary
print(f"string2 is {length:o} characters long.")  # Octal
print(f"string2 is {length:x} characters long.")  # Hex

# Older formatting using the percent sign
print("string2 is %d characters long!" % len(string2))

# ======================
# Tuples
# ======================

# Tuples () - store multiple items in a single variable and cannot be changed (immutable)
tuple_items = ("item1", "item2", "item3")
print(tuple_items)
print(type(tuple_items))  # Output: <class 'tuple'>

# Checking the index of an item in a tuple
print(tuple_items.index("item1"))  # Output: 0

# Tuple unpacking
item1, item2, item3 = tuple_items
print(item1)
print(item2)
print(item3)

# ======================
# Lists
# ======================

# Lists use [] and are ordered, changeable, and allow duplicates
list1 = ["A", "B", "C", 1, 4.0, ["A"]]
print(list1)

# Modifying list items
list1[0] = "X"
print(list1)

# Appending and inserting items
list1.append("Z")  # Adds to the end
list1.insert(1, "Y")  # Inserts at index 1

# Removing items
del list1[0]
list1.pop()  # Removes last item
list1.remove("B")  # Removes first occurrence

# Sorting lists
list1 = [5, 2, 3, 4, 8, 0]
list1.sort()  # Ascending
print(list1)

list1.sort(reverse=True)  # Descending
print(list1)

# ======================
# Dictionaries
# ======================

# Dictionaries store key-value pairs and do not allow duplicate keys.
dict1 = {"a": 1, "b": 2, "c": 3}
print(dict1)

# Accessing dictionary values
print(dict1["a"])  # Using key directly
print(dict1.get("a"))  # Using .get() method

# Retrieving all keys, values, and items
print(dict1.keys())  # Returns all keys
print(dict1.values())  # Returns all values
print(dict1.items())  # Returns key-value pairs

# Adding and modifying dictionary values
dict1["d"] = 4
dict1["a"] = 10

# Removing dictionary items
dict1.pop("a")  # Removes key and returns value
del dict1["c"]  # Deletes key without returning value

# Nested dictionaries
dict1["nested"] = {"x": 100, "y": 200}
print(dict1)

# ======================
# Sets in Python
# ======================

# Sets store multiple items but do not maintain order.
# Sets do not use keys, cannot have duplicates, and cannot be searched by index.

set1 = {"a", "b", "c"}
print(set1)  # The order may be different every time

# ======================
# Creating Sets
# ======================

# Using the set constructor to create sets
set4 = set(("b", 1, False))
print(set4)

# ======================
# Modifying Sets
# ======================

# Adding a new item to a set
set1.add("d")
print(set1)

# Updating a set with another set
set1.update(set4)
print(set1)

# Updating a set with a list
listt = ["1", "2", "3"]
print(listt)
sett = {"4", "5", "6"}
print(sett)

# Adding all elements from the list to the set
sett.update(listt)
print(sett)

# ======================
# Removing Items from a Set
# ======================

# Removing an item using remove()
sett.remove("4")
print(sett)

# ⚠️ remove() will raise an error if the value does not exist.

# Using discard() to remove an item (no error if the item is missing)
sett.discard("5")
print(sett)

# ======================
# Popping Items from a Set
# ======================

# pop() removes a random element since sets are unordered.
popped_item = sett.pop()
print(f"Popped item: {popped_item}")
print(sett)  # Remaining elements

# ======================
# Conditional Statements
# ======================

# Writing a simple if-else conditional
if True: 
    print("True")
else:
    print("False")

# Using elif to compare values
# The else statement serves as a catch-all if no conditions are met.
if 1 < 1:
    print("True")
elif 1 <= 0:
    print("False")
else:
    print("Neither condition was met")

# ======================
# Elif Behavior (Only First Matching Condition Runs)
# ======================

# Only the first matching elif statement will execute.
# Once a condition evaluates to True, the rest of the elifs are skipped.

if 1 < 1:
    print("True")
elif 1 <= 0:
    print("False")
elif 0 == 0:  # This is True, so this block runs
    print("Zero is zero")
else:
    print("Neither")

# ======================
# Logical Operators: AND, OR
# ======================

# Using the 'and' operator (both conditions must be True)
if 1 > 0 and 0 < 1:
    print("1 > 0 and 0 < 1")  # This will print

# Using the 'or' operator (only one condition must be True)
if 1 > 0 or 0 > 1:
    print("At least one condition is True")  # This will print

# Using 'or' inside parentheses with 'and' for priority evaluation
# The expression inside () is evaluated first
if (1 > 0 or 0 > 1) and 1 == 1:
    print("Both conditions evaluated to True")

# ======================
# Shorthand Conditional Statements
# ======================

# Single-line if statement
if 0 < 1: print("True")  # Shorthand format

# Ternary operator (short form of if-else)
print("1 >= 1") if 1 >= 1 else print("1 < 1")

# Long-form equivalent of the above ternary
if 1 >= 1: 
    print("1 >= 1")
else: 
    print("1 < 1")

# ======================
# Multi-Level Ternary (Nested Ternary)
# ======================

# Equivalent to:
# if 0 > 1:
#     print("1")
# elif 0 < 1:
#     print("2")
# else:
#     print("3")

print("1") if 0 > 1 else print("2") if 0 < 1 else print("3")

# ======================
# Loops in Python
# ======================

# Why use loops?
# Instead of writing repetitive code manually, we use loops to automate tasks.

# This is inefficient:
a = 1
print(a)
a += 1
print(a)
a += 1
print(a)
a += 1
print(a)
a += 1
print(a)
a += 1
print(a)

# ======================
# While Loops
# ======================

# A while loop continues running as long as the condition remains True.
# This example increments 'a' by 1 until 'a < 5' is False.

a = 1
while a < 5:
    a += 1
    print(a)

# ======================
# For Loops
# ======================

# A for loop executes a set number of times.
for i in [0, 1, 2, 3, 4, 5, 6]:
    print(i + 6)  # Adding 6 to each iteration

print("--------")

# Instead of manually listing numbers, we can use the range() function.
for i in range(70):  # Loops from 0 to 69
    print(i + 6)

print("-------")

# ======================
# Nested Loops
# ======================

# j iterates first, then i iterates
for i in range(3):
    for j in range(3):
        print(i, j)

# ======================
# Loop Control Statements
# ======================

# 1. Break: Stops the loop when a condition is met
for i in range(5):
    if i == 2: 
        break  # Loop stops when i == 2
    print(i)

print("------")

# 2. Continue: Skips the current iteration and moves to the next
for i in range(5):
    if i == 2: 
        continue  # Skips 2 and continues with the loop
    print(i)

print("------")

# 3. Pass: Placeholder when you need a loop or function but don't want it to execute yet
for i in range(5):
    if i == 2: 
        pass  # Does nothing, just a placeholder
    print(i)

print("------")

# ======================
# Looping Over Strings
# ======================

# You can loop through each character in a string
for c in "lets do a loop":
    print(c)

print("------")

# ======================
# Looping Over Dictionaries
# ======================

# You can iterate over dictionary keys and values using .items()
sample_dict = {"key": "value", "key2": "value2", "key3": "value3"}
print(sample_dict)
print(type(sample_dict))
print("-----------")

for key, value in sample_dict.items():
    print(key, value)

# ======================
# Reading and Writing Files in Python
# ======================

# We can create a file handle by passing the file location to the open() function.
# If the file does not exist, we will receive an error.
f = open('top-100.txt')
print(f)  # Prints file object info

# ======================
# File Modes in Python
# ======================

# The default mode when opening a file is 'r' (read mode).
# Other modes:
# 'r'  - Read (default)
# 'w'  - Write (creates/overwrites a file)
# 'a'  - Append (adds to an existing file)
# 'x'  - Create (fails if the file already exists)
# 'b'  - Binary mode (e.g., images)
# 't'  - Text mode (default)

# Here, we specify read mode ('r') and text mode ('t')
f = open('top-100.txt', 'rt')
print(f)

# ======================
# Reading a File
# ======================

# Reading the entire contents of a file as a single string
print(f.read())

# Reading the file line by line using readlines()
f = open('top-100.txt', 'rt')
print(f.readlines())  # Returns a list of lines

# If we try to read the file again, we get an empty list
# This happens because Python has already reached the **end of the file**
print(f.readlines())

# ======================
# Using seek() to Reset File Pointer
# ======================

# We use seek(0) to move the file pointer back to the beginning
f.seek(0)
print(f.readlines())

# ======================
# Iterating Over a File Line by Line
# ======================

# Using a for loop to read each line (with strip() to remove leading/trailing whitespace)
f.seek(0)
for line in f:
    print(line.strip())

# When we're done using the file, we should close it
f.close()

# ======================
# Writing to a File
# ======================

# Opening a file in write ('w') mode.
# This **creates** the file if it doesn’t exist OR **overwrites** an existing file.
f = open("test.txt", "w")
f.write("testing")  # Writes "testing" to the file
f.close()

# Reading the contents to verify
f = open("test.txt", "rt")
print(f.read())
f.close()

# ======================
# Appending to a File
# ======================

# Opening a file in append ('a') mode.
# This **adds** content to the existing file without overwriting.
f = open("test.txt", "a")
f.write("testinggggg")  # Appends "testinggggg"
f.close()

# Reading the file again to see the new content
f = open("test.txt", "rt")
print(f.read())
f.close()

# ======================
# File Attributes
# ======================

# Checking file attributes
print(f.name)    # Specifies the name of the file
print(f.closed)  # Returns True if the file is closed, False if it's still open
print(f.mode)    # Returns the mode the file was opened in (e.g., 'rt')

# ======================
# Using 'with open()' (Recommended)
# ======================

# The 'with' statement is preferred for opening files as it **automatically closes** the file when done.
with open("test.txt", "r") as f:
    content = f.read()
    print(content)  # Prints file contents

# The file is **automatically closed** after the 'with' block ends.

# ======================
# Iterating Over Large Files (Example: rockyou.txt)
# ======================

# The 'with' statement ensures the file is properly closed.
# We specify encoding='latin-1' because rockyou.txt contains encoded passwords.
with open('rockyou.txt', encoding='latin-1') as f:
    for line in f:
        pass  # Iterating over the file without storing it in memory (efficient)

# ======================
# User Input in Python
# ======================

# Taking user input and printing it
test = input()  # User enters input
print(test)  # Prints user input

# ======================
# Prompting the User for Input
# ======================

# Assigning a string to prompt the user
test = input("Enter the IP: ")
print(test)  # Prints entered IP

# ======================
# Creating an Infinite Loop with User Input
# ======================

# Example: An infinite loop that continues until the user types 'exit'
while True:  # Infinite loop
    test = input("Enter target IP: ")  # Prompt user
    print(">>>> {}".format(test))  # Print formatted input

    # Exit condition
    if test.lower() == "exit":  # Convert input to lowercase for case insensitivity
        print("Exiting program...")
        break  # Breaks out of the loop
    else: 
        print("Exploiting...")  # Simulated action
        
# ======================
# Error Handling and Exceptions (try-except blocks)
# ======================

# The try block lets you test a block of code for errors.
# The except block handles errors.
# The finally block will always execute, regardless of whether an exception occurs.

# ======================
# Example of an Indentation Error
# ======================

# This will cause an indentation error
# Uncommenting this will cause a SyntaxError:
# print(1)
#     print(2)  # IndentationError: unexpected indent

# ======================
# Handling a File Not Found Error
# ======================

# If we try to open a file that doesn't exist, an error occurs.
# Instead of letting Python throw an error, we handle it with an exception.

try: 
    f = open("filedoesntexist")  # This will trigger an exception
except:
    print("This file doesn't exist")  # Handles any error

# ======================
# Printing the Actual Error Message
# ======================

# If we want to output the actual Python error:
try: 
    f = open("filedoesntexist") 
except Exception as e:
    print(e)  # Example output: [Errno 2] No such file or directory: 'filedoesntexist'

# ======================
# Handling Specific Exceptions
# ======================

# Instead of catching all exceptions, we can specify which errors to handle.
# This prevents exposing sensitive data from raw Python error messages.

try: 
    f = open("filedoesntexist") 
except FileNotFoundError:  # Handle only file-not-found errors
    print("The file does not exist!")
except Exception as e:
    print(e)  # Catch any other unexpected exceptions

# ======================
# Using the finally Block
# ======================

# The 'finally' block will always execute, regardless of whether an error occurs.

try: 
    f = open("filedoesntexist") 
except FileNotFoundError: 
    print("The file does not exist!")
except Exception as e:
    print(e)
finally: 
    print("This message will always print.")  # Runs no matter what

# ======================
# Raising Exceptions
# ======================

# We can manually raise an exception using the raise keyword.
n = 100
if n == 0:
    raise Exception("n can't be 0!")  # Raises an error if n is 0

# ======================
# Validating User Input with Exceptions
# ======================

# If the user inputs 0, we raise an exception.
# If the user enters non-numeric input, we catch and handle the ValueError.

try:
    n = int(input("Please input a number: "))  # Convert input to an integer

    if n == 0:
        raise Exception("n can't be 0!")  # Raising if user inputs 0

    print("Your number is " + str(n))  # Convert n to string for printing

except ValueError:  # Handle non-integer inputs
    raise Exception("n must be a number")  # Raising a new exception

#!/bin/python3

# ======================
# Comprehensions in Python
# ======================

# We can create a list manually
list1 = ['a', 'b', 'c']
print(list1)

# Or we can use a list comprehension to create a new list from an existing one
list2 = [x for x in list1]  # For every item in list1, add it to list2
print(list2)

# Conditional list comprehension
# Only add items from list1 to list3 if the item equals 'a'
list3 = [x for x in list1 if x == 'a']
print(list3)

# Generate a list of numbers from 0 to 4 using range()
list4 = [x for x in range(5)]
print(list4)

# Apply a function (hex) to each item during comprehension
list5 = [hex(x) for x in range(5)]
print(list5)

# Conditional expression inside a list comprehension
# If x > 0, add hex(x), else add "x"
list6 = [hex(x) if x > 0 else "x" for x in range(5)]
print(list6)

# Square each value in the range using list comprehension
list7 = [x * x for x in range(5)]
print(list7)

# Add only numbers 0 and 1 from the range
list8 = [x for x in range(5) if x == 0 or x == 1]
print(list8)

# ======================
# Nested Comprehensions
# ======================

# Creating a nested list (list of lists)
list9 = [['1', '2', '3'], ['4', '5', '6'], ['7', '8', '9']]
print(list9)

# Flattening a nested list using a nested list comprehension
# y for x = each item inside sublists
# x for y = each sublist
list10 = [y for x in list9 for y in x]
print(list10)

# ======================
# Set Comprehension
# ======================

# Creating a set using comprehension
# Adds x+x (sum) for each x in the range
set1 = {x + x for x in range(5)}
print(set1)

# ======================
# String Comprehension and Joining
# ======================

# Iterate through a string and create a list of characters
list11 = [c for c in "string"]
print(list11)

# Equivalent longhand version using a for loop
list12 = []
for c in "string":
    list12.append(c)
print(list12)

# Join the list back into a string with no separator
print("".join(list11))  # Output: string

# Join the list with a separator ("-")
print("-".join(list11))  # Output: s-t-r-i-n-g

# ======================
# Functions in Python
# ======================

# Functions are used to execute reusable blocks of code.
# They help reduce redundancy and improve modularity.

# Declaring a simple function
def function1(): 
    print("Hello from function1.")

function1()  # Calling the function

# Returning a value from a function
def function2():
    return "Hello from function2!"

return_from_function2 = function2()  # Assigning return value to a variable
print(return_from_function2)

# ======================
# Functions with Parameters
# ======================

# This function requires a parameter 's'
def function3(s):
    print("\t{}".format(s))  # Using the format method to print the parameter

function3("parameter")  # Passing a string

# Function with multiple parameters
def function4(s, g): 
    print("\t{}\t{}".format(s, g))

function4("param s", "param g")
function4(s="the", g="thing")  # Keyword arguments
function4(g="the", s="thing")  # Order doesn’t matter with keywords

# Setting default parameter values
def function5(s="default"):
    print("{}".format(s))

function5()  # Uses default
function5("custom value")  # Overrides default

# ======================
# Variable-Length Arguments
# ======================

# *args allows an arbitrary number of positional arguments
def function6(s1, *more):
    print("{} {}".format(s1, " ".join(more)))

function6("function6")
function6("function6", "a")
function6("function6", "a", "b", "c")

# **kwargs allows an arbitrary number of keyword arguments
def function7(**ks):
    for k in ks:
        print(k, ks[k])

function7(a="1", b="2", c="3", d="4")

# ======================
# Passing Different Data Types
# ======================

def function8(s, f, i, l):
    print(type(s))  # str
    print(type(f))  # float
    print(type(i))  # int
    print(type(l))  # list

function8("string", 1.0, 1, ['l', 'i', 's', 't'])

# ======================
# Variable Scope
# ======================

# Global variable
v = 100
print(v)

def function9():
    print(v)  # Accessing global variable

function9()

# Uncommenting this will raise an error due to local variable usage without assignment
# def function9():
#     v += 1  # UnboundLocalError
#     print(v)

# Use 'global' to modify a global variable from inside a function
def function9():
    global v
    v += 1
    print(v)

function9()

# Local variable shadows global one
def function9():
    v = 10  # Local variable
    v += 1
    print(v)

function9()

# ======================
# Function Calling Another Function
# ======================

def function10():
    print("Hello from function10")

def function11():
    function10()
    print("Hello from function11")

function11()

# ======================
# Recursion (Function Calling Itself)
# ======================

# Recursive function (with base case to prevent infinite loop)
def function12(x):
    print(x)
    if x > 0:  # Base case
        function12(x - 1)

function12(5)

# Equivalent logic using a while loop instead of recursion
def function13(x):
    while x >= 0: 
        print(x)
        x -= 1

function13(5)

# ======================
# lambda functions
# ======================

#lambdas an anonymous function without a name
#can have any number of arguments, but can only have one expression
#cannot use multiple lines in your lambda function

#example lambda 
add_4 = lambda x : x+4 #take the argument and add 4
print(add_4(4))

#passing multiple paramaters to the lambada. Takes x adds y
add = lambda x, y: x+y
print(add(10,4))

#using standard function to do the same
def addf(x,y):
    return x + y
print(addf(1,2))

#using lambda
print((lambda x, y: x + y)(10,4))

#lambda for is even or odd
is_even = lambda x: x % 2 == 0 
print(is_even(1))
print(is_even(2))

#lambda taking input and breaking the input into lists of defined size
blocks = lambda x, y: [x[i:i+y] for i in range(0, len(x), y)]
print(blocks("string", 2))

#ord returns the integer equivalent of the input
to_ord = lambda x: [ord(i) for i in x]
print(to_ord("ABCD"))

#doing the same ord function, we can see lambda does in 1 line what this does in 5
def to_ord2(x):
    ret = []
    for i in x: 
        ret.append(ord(i))
    return ret 

print(to_ord("ABCD"))

#sorting with lambda
people = [{'name': 'John', 'age': 25}, {'name': 'Alice', 'age': 30}]
sorted_people = sorted(people, key=lambda person: person['age'])
print(sorted_people)

nums = [1, 2, 3, 4, 5]
print(list(map(lambda x: x * 2, nums)))  # [2, 4, 6, 8, 10]

# ======================
# Sorting and Mapping with Lambda
# ======================

# sorting with lambda
# This is a list[] of dictionaries. Each dictionary represents a person with a name and age.
# {} represents a dictionary
# A dictionary stores key-value pairs, such as "name": "John" or "age": 25.
people = [{'name': 'John', 'age': 25}, {'name': 'Alice', 'age': 30}]

# The sorted() function returns a new sorted list from the iterable.
# 'key' is a parameter that lets you specify a function to determine the sort order.
# In this case, we're using a lambda function to sort by the value of the 'age' key in each dictionary.
# lambda person: person['age'] takes a dictionary and returns its 'age' value.
# So the sort is based on that returned age.
sorted_people = sorted(people, key=lambda person: person['age'])

# This will output the list sorted by age in ascending order.
print(sorted_people)  # [{'name': 'John', 'age': 25}, {'name': 'Alice', 'age': 30}]

# map() with lambda
# This is a list of integers.
nums = [1, 2, 3, 4, 5]

# map() applies a function to every item in the iterable.
# Here, we use a lambda to multiply each item by 2.
# lambda x: x * 2 is applied to every number in nums.
# map() returns a map object, so we convert it to a list for printing.
print(list(map(lambda x: x * 2, nums)))  # Output: [2, 4, 6, 8, 10]


# ======================
# Python Packages
# ======================

# We can use https://pypi.org/ to view Python packages and their documentation.

# pip install pwntools - installs the package
# from pwn import * - imports everything from the 'pwn' module (provided by pwntools)

# pip list - displays all installed packages and their versions
# pip freeze - shows installed packages in a format suitable for saving to requirements.txt

# pip install pwntools==4.5.1 - installs a specific version
# pip uninstall pwntools - uninstalls the package

# ======================
# Using requirements.txt
# ======================

# You can define dependencies in a requirements.txt file like this:
# pwntools==4.14.0
# pyelftools==0.29
# Pygments==2.5.2
# PyNaCl==1.4.0

# pip install -r requirements.txt - installs all listed packages
# pip freeze > requirements.txt - saves current environment's packages to a requirements file

# ======================
# Python Virtual Environments
# ======================

# A virtual environment allows an isolated Python environment.
# You can install multiple versions of Python packages without conflicts.
# By default, virtual environments do NOT include any globally installed packages.
# Useful when you need different versions of packages for testing or project isolation.

# pip install virtualenv       - install the virtualenv package
# python3 -m venv env          - create a virtual environment named 'env'
# source env/bin/activate      - activate the virtual environment
# (env) will appear in the prompt after activation:
# Example: (env)─(kali㉿kali)-[~/python/virtual]

# deactivate                  - exit the virtual environment

# which python3               - shows which Python binary is being used
# In virtual env: /home/kali/python/virtual/env/bin/python3
# On host system: /usr/bin/python3

# ======================
# Python sys Module
# ======================

# The sys module provides access to variables and functions that interact with the Python runtime environment.
# It is part of the standard library — no installation required.
# Common uses include command-line arguments, version info, standard input/output handling, and exiting scripts.

import sys

# Basic sys info
print(sys.version)        # Prints the Python version being used
print(sys.executable)     # Path to the Python binary (same as 'which python3')
print(sys.platform)       # Shows the platform (e.g., 'linux', 'win32', 'darwin')

# ======================
# Using sys.stdin and sys.stdout
# ======================

# sys.stdin: Reads from standard input (e.g., piped data or user input)
# sys.stdout: Writes to standard output

# Example: Echo loop until 'exit' is typed
for line in sys.stdin:
    if line.strip().lower() == "exit":  # Case-insensitive check, trims whitespace
        break
    sys.stdout.write(">> {}".format(line))  # Echoes back user input

# ======================
# Progress Bar Using \r and sys.stdout
# ======================

import time

# This loop uses '\r' to overwrite the same line for a progress bar effect
for i in range(0, 51):
    time.sleep(0.1)
    sys.stdout.write("{} [{}{}]\r".format(i, '#' * i, '.' * (50 - i)))
    sys.stdout.flush()  # Ensure the line is written immediately

sys.stdout.write("\n")  # Move to a new line after the loop finishes

# Final output looks like:
# 50 [##################################################]

# ======================
# Command-line Arguments with sys.argv
# ======================

print(sys.argv)  # List of arguments passed to the script (first item is script name)

# We can use len(sys.argv) to validate argument count
if len(sys.argv) != 3:
    print("[X] To run {} enter a username and password.".format(sys.argv[0]))
    sys.exit(5)  # Exit with code 5 if arguments are missing

# Assigning arguments
username = sys.argv[1]
password = sys.argv[2]
print("{} {}".format(username, password))

# ======================
# Module Search Path and Loaded Modules
# ======================

print(sys.path)     # Lists directories Python searches for modules
print(sys.modules)  # Dictionary of all currently loaded modules

# ======================
# Exit Codes
# ======================

# sys.exit([code]) lets us exit with a specific status code
# Common conventions:
# - 0: Success
# - Non-zero: Error (can be custom like 1, 2, 5, etc.)

sys.exit(0)  # Exit with success

# After running a script, you can check the exit code in Linux with:
# $ echo $?

# ======================
# Python requests Module
# ======================

# Use https://pypi.org/ to explore Python packages and their usage.

# requests is a popular library used to interact with web applications.
# It supports sending GET, POST, DELETE requests and more — great for API testing and automation.

# pip install requests - install the requests package
import requests

# Basic GET request
x = requests.get('http://httpbin.org/get')
print(x)
print(x.headers)                     # Print all response headers
print(x.headers['Server'])          # Print specific header
print(x.status_code)                # Print status code (e.g., 200)

# Check for a specific vulnerable server version
def unicornsearch():
    x = requests.get('http://httpbin.org/get')
    if x.headers['Server'] == "gunicorn/19.9.0":
        print(x.headers['Server'])
    else:
        print("No vulnerable servers found")

unicornsearch()

# Handling status codes
if x.status_code == 200:
    print("Success!")
elif x.status_code == 404:
    print("Not found!")

print(x.elapsed)        # Time taken for the request
print(x.cookies)        # CookieJar object
print(x.content)        # Byte content
print(x.text)           # Unicode text

# ======================
# Sending Query Parameters
# ======================

# Add parameters with the 'params' argument
x = requests.get('http://httpbin.org/get', params={'id': '1'})
print(x.url)  # Outputs: http://httpbin.org/get?id=1

# Alternative direct query in URL
x = requests.get('http://httpbin.org/get?id=2')
print(x.url)

# Add custom headers
x = requests.get('http://httpbin.org/get', params={'id': '3'}, headers={'Accept': 'application/json'})
print(x.text)

# Add arbitrary headers (e.g., "Test-Header")
x = requests.get('http://httpbin.org/get', headers={'Test-Header': 'test'})
print(x.text)

# DELETE request
x = requests.delete('http://httpbin.org/delete')
print(x.text)

# POST request with form data
x = requests.post('http://httpbin.org/post', data={'a': 'b'})
print(x.text)

# Upload file with multipart/form-data
files = {'file': open('google.png', 'rb')}
x = requests.post('http://httpbin.org/post', files=files)
print(x.text)

# Basic Authentication
x = requests.get('http://httpbin.org/get', auth=('username', 'password'))
print(x.text)

# ======================
# Handling SSL Certificates
# ======================

# By default, requests validates SSL certs
# This will raise an error if the cert is expired:
# x = requests.get('https://expired.badssl.com')  # Certificate verify failed

# Ignore SSL cert errors using verify=False
x = requests.get('https://expired.badssl.com', verify=False)
print(x.text)

# Disable redirects (e.g., GitHub HTTP to HTTPS redirect)
x = requests.get('http://github.com', allow_redirects=False)
print(x.headers)

# Set a timeout for the request
x = requests.get('http://httpbin.org/get', timeout=5)
print(x.content)

# ======================
# Cookies
# ======================

# Send cookies with a request
x = requests.get('http://httpbin.org/cookies', cookies={'a': 'b'})
print(x.content)

# Using a session for persistent cookies
session = requests.session()
session.cookies.update({'a': 'b'})
print(session.get('http://httpbin.org/cookies').text)
print(session.get('http://httpbin.org/cookies').text)  # Cookie reused in both requests

# ======================
# Working with JSON
# ======================

x = requests.get('https://api.github.com/events')
print(x.json())  # Automatically parses JSON response

# ======================
# Download and Save an Image
# ======================

x = requests.get('https://www.google.com/images/branding/googlelogo/1x/googlelogo_light_color_92x30dp.png')
with open('google_logo.png', 'wb') as f:
    f.write(x.content)
    
# ======================
# Pwntools
# ======================

#pwntools - one of the most powerful modules for hackers

#pip install pwntools - install pwntools

#importing pwntools
from pwn import *

print(cyclic(50)) #creating a de Bruijn sequence or cyclic sequence
print(cyclic_find("laaa")) #this will show us that laaa is at offset 44 in the 50 byte sequence

#we can use shellcraft to create shellcode in assembly and asm
print(shellcraft.sh()) #assembly 
print(hexdump(asm(shellcraft.sh()))) #asm

p = process("/bin/sh") #opening local process at /bin/sh
p.sendline("echo hello;") #sending the line echo hello to the process using ; to end 
p.interactive() #calling the process interactively 


#we can also work with remote processes
r = remote("127.0.0.1", 1234) #setting remote host and port
r.sendline("hello!") #sending hello string 
r.interactive() #calling the process interactively
r.close() #exiting the process when done


print(p32(0x13371337))  # Packs 32-bit integer into little-endian byte format
print(hex(u32(p32(0x13371337))))  # Unpacks 4-byte value back into int


l = ELF('/bin/bash')

print(hex(l.address)) #view base address
print(hex(l.entry))

print(hex(l.got['write']))
print(hex(l.plt['write']))

#searching for
for address in l.search(b'/bin/sh\x00'):
    print(hex(address))

#searching for a jmp esp
print(hex(next(l.search(asm('jmp esp')))))

r = ROP(l)
print(r.rbx)

print(xor("A", "B"))
print(xor(xor("A", "B"), "A"))

#base64 encoding
print(b64e(b"test"))

#base64 decoding
print(b64d(b"dGVzdA=="))

#md5sum
print(md5sumhex(b"hello"))

#sha1
print(sha1sumhex(b"hello"))

#viewing bits representation
print(bits(b'a'))

#unbit representation
print(unbits([0, 1, 1, 0, 0, 0, 0, 1]))




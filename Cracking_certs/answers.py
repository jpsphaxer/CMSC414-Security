import os


file_name = raw_input("Enter the output file name:  ")
small = int(input("Enter small prime: "))
big = int(input("Enter big prime: "))
exp = int(input("Enter exponent: "))

f = open(file_name, "w")
f.write(str(small)+"\n")
f.write(str(big)+"\n")
f.write(str(exp)+"\n")
f.close()
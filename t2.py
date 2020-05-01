import matplotlib.pyplot as plot
import numpy as np
import random

print("hola")
x=[1,2,3,4,5]
y=[34,3,12,24,56]
plot.scatter(x,y)
plot.show()
c=np.polyfit(x,y,5)
print(c)
xx = []

cantidad = 5
dias = 10
for x in range(dias-1):
  xx.append(1+(x*1/2))
yy=np.polyval(c,xx)

print(xx)
print(yy)
plot.scatter(xx,yy)
plot.show()
from scipy.interpolate import lagrange
import matplotlib.pyplot as plot
import numpy as np

print("hola")
x=[1,2,3,4,5]
y=[34,3,12,24,56]
plot.scatter(x,y)
plot.show

c=lagrange(x,y)
print(c)

xx = []
cantidad=5
dias=10
xx = np.linspace(1,5,10)
yy=c(xx)

print(xx)
print(yy)
print("-----------")
print(c(4))

plot.scatter(xx,yy)
plot.show()



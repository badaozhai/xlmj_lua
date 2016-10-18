--
-- Created by IntelliJ IDEA.
-- User: Administrator
-- Date: 2016/10/18
-- Time: 17:34
--

--文件对象的创建
file = io.open("demo.txt","w+");

var = string.format("%d %s\n", 1, "haha")

print(var)

file:write(var)



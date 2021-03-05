这是一个文件过滤驱动，代码基于https://blog.csdn.net/wishfly/article/details/90023097

思想来自：https://www.youtube.com/watch?v=HFO8GCGQcUc

该驱动默认工作的环境为 win10 x64 1709   如果需要在别的环境运行需要将代码中所有的PROC + 0x450改成对应操作系统判断对应进程名偏移然后进行编译。  

因为是拿普通进程token去判断 所以需要以普通权限运行test.exe才开始工作，test.exe是一个死循环，避免进程结束，像这样
void main(){
while(1){};
}

如果您想过滤windows自带进程的IRP，代码中这样的代码可以注释掉，我在Windows比较早的版本前光是挂着就可以记录非常多windows自身的危险行为，但在20h2上，如果什么都不做，我一个都记录不到了。  
    if (!strcmp(NAME, "mscorsvw.exe")  
        || !strcmp(NAME, "svchost.exe")    
        || !strcmp(NAME, "ngen.exe")   
        || !strcmp(NAME, "MsMpEng.exe")    
        || !strcmp(NAME, "sppsvc.exe")   
        || !strcmp(NAME, "System")    
        || !strcmp(NAME, "wermgr.exe")   
        || !strcmp(NAME, "TiWorker.exe")   
        || !strcmp(NAME, "sedsvc.exe")   
        || !strcmp(NAME, "wuauclt.exe")   
        || !strcmp(NAME, "explorer.exe")    
        || !strcmp(NAME, "spoolsv.exe")   

记录可疑日志保持在c盘根目录上    

BoomUsersCL.txt 记录可能被符号链接劫持文件删除信息    

BoomUsersCreate.txt 记录可能被符号链接劫持文件创建和写入的信息     

BoomKernel.txt 记录在内核中创建的文件 需要通信 后来发现没什么用，因为我没有判断是否允许普通用户通信   

BoomUsersMove.txt 记录可能被符号链接劫持文件移动的信息   

copyfile被记录在BoomUsersCreate.txt ，因为copyfile不是设置文件信息，这种情况需要分析文件是怎么创建的。   

因为我不是开发专家，此驱动并不完全准确，是否可利用需要您自己去看，而怎么去看需要经验和尝试。

![](https://github.com/y5s5k5/code/blob/main/%E5%9B%BE%E5%83%8F%208.png)  



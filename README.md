# 02
实现进程隐藏
编写一个进程，能够实现进程隐藏，可以根据课程中提到的方法进行进程隐藏，（伪装进程名、将进程设为服务，进程注入等方式进行隐藏）。
隐藏进程
	实现原理:通过HOOKAPI ZwQuerySystemInformation可以实现进程隐藏.这是因为EnumProcess或者CreateToolHelp32Snapshot遍历进程,都是通过ZwQuerySystemInformation函数来检索系统进程信息的.
	实现方法:内联HOOK或者IAT HOOK
	1. 获取ZwQuerySystemInformation函数地址
	2. 根据32和64位版本,计算偏移,修改函数前xx字节数据
	3. 先修改页属性,再修好内存数据,恢复页属性
	4. 在My_ZwQuerySystemInformation函数中判断是否检索要隐藏进程,若是隐藏进程,遍历检索结果,剔除隐藏进程的信息,将修改数据返回

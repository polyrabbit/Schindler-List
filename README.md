# Schindler's List

我曾经当过一段时间的助教，实在是讨厌每次的点名，大概是因为以下的几个原因：

1. 奇葩的名字。有些字可能这辈子也不会再碰到第二次了，而且我的普通话也太烂，尴尬。
2. 代签。为防止某些好心人的代签，我心须时刻留意，这让我回想起了高中时帮语文老师检查谁没有交作业的情景。
3. 时间。嗯，一堂课如果有百十来号人，没有十几分钟是签不完的。

因此，这世上便诞生了`Schindler'sList`这一签到神器，自从有了它，妈妈再也不用担心我的签到综合症了。

### 用法
* Windows

    如果你没有Python解释器，或者你不知道什么是Python，请先[下载](http://python.org/ftp/python/2.7.5/python-2.7.5.msi)安装（这就像你想打开word文档必须要先安装office一样）。And then,
    1. [下载](https://github.com/polyrabbit/Schindler-List/archive/master.zip)并解压，进入到程序目录后双击运行schindler.py，你会看到一个黑窗口，不用怕，那不是黑洞，上面写着`Server is listening on x.x.x.x:80`，x.x.x.x应该是四个具体的数字，
那代表了你的IP。
    2. 将这个IP地址告诉你的学生，让他们来访问这个IP（就像访问www.baidu.com一样），并让他们在浏览器弹出的窗口上填入自己在[教务网](http://jw.dhu.edu.cn)的学号和密码，研究生请填入[信息门户](http://my.dhu.edu.cn)的账号。
    3. 没有第三步。
    4. 当同学们都完成之后，请关掉这个程序（点右上角的X，恭喜你答对了），然后在同一个目录下你会找到`Schindler'sList.txt`这个文件，它就是我们最终想要的出勤名单，打开它，你和你的小伙伴们都会惊呆的。

* Linux
  
    Happy hacking :smile: 

### 原理
>怎样向别人证明这就是我，这他妈是个哲学问题。

在这个软件里，我将一个人在[教务网](http://jw.dhu.edu.cn)上的账号用作他的身份证明，当然这是建立在一般人不会随便把他的账号告诉别人的基础之上。很显然这样的假设对某些求签到若渴的学生是不成立的，
所以我对账号和电脑进行了绑定，也就是说如果A君在这台电脑上签到过了，那他就不可以再在这台电脑上帮B君代签了，除非A君自己不签到，而把机会让给B君，这样无私的[友|爱|基]情，就放过吧。

>你怎么知道这个学生填写的学号和密码是不是正确的？

我不知道呀，但是我们的[教务网](http://jw.dhu.edu.cn)会知道，我只要把他提供的学号和密码拿去登录[教务网](http://jw.dhu.edu.cn)，能成功不就证明这是正确的么。当然，这一切都是机器做的，不要人去手动操作。如果你的安全意识稍微强一点的话，你可能会担心，学生把自己的学号和密码提交上来了，这个程序会记录么？嗯，或许将来某天会吧，但现在绝对不会，要不放心你可以逐字检查我的代码，看看哪里是不是留有后门。


好吧，我承认第一句话我说谎了，其实我是知道你密码的，方法就在我的另一个**PRIVATE** [repo](https://github.com/polyrabbit/dhu-jw-sql-injection)里面（别点，你什么也看不到）。关于这个漏洞我老早就已经向学校报告过了，但一直没人鸟我，无语～～

>整个签到过程有没有漏洞？

当然有了，任何系统都会有不同程度的漏洞。根据上面的描述，A君在自己签到完之后，只要再找一台空闲电脑就可以帮B君签到了，这个我也没有办法阻止。如果哪天你在生成的`Schindler'sList.txt`文件中看到同一个IP下有两个不同的学生签到的话，那就证明这个软件失效了，请不要再用下去。

欢迎各种[**建议与反馈**](https://github.com/polyrabbit/Schindler-List/issues)。

### Liscense
LGPL v3


[![Bitdeli Badge](https://d2weczhvl823v0.cloudfront.net/polyrabbit/schindler-list/trend.png)](https://bitdeli.com/free "Bitdeli Badge")


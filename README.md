文件名 | 说明
--- | ---:
100keys.txt|key 文件
attack_shiro.py|攻击检测脚本 支持 CBC、GCM 两种模式
attack_shiro_py3.py|适配python3 支持 CBC、GCM 两种模式
cookie.py|生成cookie 脚本
decode_rememberme_py3.py|还原rememberMe密文
url.txt|待检测的url列表
ysoserial-0.0.7-SNAPSHOT-all.jar|反序列化poc生成框架
success文件夹|攻击成功生成的文件


>ysoserial-0.0.7-SNAPSHOT-all.jar 支持的回显模式
```java
  /**
     * 参考：https://xz.aliyun.com/t/7535
     *
     * name="http-bio-8080",type=GlobalRequestProcessor         //tomcat7
     * name="http-nio-8080",type=GlobalRequestProcessor         //tomcat8
     *
     * 模式：tomcat
     * TOMCAT_DEFAULT:   // 直接执行命令，明文
     *       CMD:whoami
     *
     * 模式：tomcatbase64
     * TOMCAT_BASE64    //  CMD 命令为base64编码，返回的结果也是base64编码
     *       CMD:base64
     *
     * 参考：https://raw.githubusercontent.com/buptchk/ysoserial/master/src/main/java/ysoserial/payloads/util/Gadgets.java   #createTemplatesImplTomcatEcho2
     *
     * 模式：tomcatbody
     * TOMCAT_BODY_1   //回显在body，需添加如下2个头
     *
     *       cmdpasskey: tomcat
     *       CMD: dir
     *
     * 参考： https://blog.csdn.net/fnmsd/article/details/106890242?spm=1001.2014.3001.5501
     * 模式： class1,classloader
     *       cmd:whoami
     *       
     * 模式：writefile
     * Thread.currentThread().getContextClassLoader().getResource("").getPath();
     * 
     * 模式：witefile2
     * System.getProperty("catalina.base")
     *       
     */
```

package com.xr.shiro.util;


import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.*;
import org.apache.shiro.config.IniSecurityManagerFactory;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.Factory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class testShiro {
    private static final transient Logger logger = LoggerFactory.getLogger(testShiro.class);

    public static void main(String[] args) {
        //1. 这里的SecurityManager是org.apache.shiro.mgt.SecurityManager
        // 而不是java.lang.SecurityManager
        // 加载配置文件
        Factory<SecurityManager> factory  = new IniSecurityManagerFactory("classpath:shiro.ini");

        //解析配置文件得到securityManager实例
        SecurityManager securityManager = factory.getInstance();
        //将得到的实例securityManager装配到SecurityUtils
        SecurityUtils.setSecurityManager(securityManager);


        //获取当前得到subject，进行操作，subject得到得事当前登录的用户
        Subject currentUser = SecurityUtils.getSubject();
        //得到session属性进行配置
        Session session = currentUser.getSession();
        //设置一个键和值
        session.setAttribute("a","胖玻璃球就6个");
        //根据key得到值
        String  str = (String)session.getAttribute("a");
        //把得到的值和绑定的值进行比较
        if("胖玻璃球就6个".equals(str)){
            logger.info("得到了正确的值："+"["+str+"]");
        }
        //用当前用户进行登录
        if(!currentUser.isAuthenticated()){
            //如果该用户没有登录
            UsernamePasswordToken token = new UsernamePasswordToken("guest","123456");
            //是否记住该用户
            token.setRememberMe(true);
            try {
                currentUser.login(token);
                logger.info("用户【"+currentUser.getPrincipal()+"】登陆成功！！");

                //查看用户拥有的角色  hasRole
                if(currentUser.hasRole("admin")){
                    logger.info("您有admin角色！");
                }else{
                    logger.info("你有个鸡毛admin");
                }

                if(currentUser.hasRole("role1")){
                    logger.info("您有role1角色");
                }else{
                    logger.info("你有个鸡毛role1角色");
                }

                if(currentUser.hasRole("role2")){
                    logger.info("您有role2角色");
                }else{
                    logger.info("你有个鸡毛role2角色");
                }

                //判断用户是否拥有数组内的权限  isPermitted 可以同时判断多个不需要一个一个判断
                String[] strings = {"洗脚权限", "piao娼权限", "洗澡权限"};
                boolean[] permitted = currentUser.isPermitted(strings);

                for (int i=0;i<permitted.length;i++){
                    if(permitted[i]){
                        logger.info("您拥有【"+strings[i]+"】权限");
                    }else{
                        logger.info("你没有【"+strings[i]+"】权限，你在想屁吃");
                    }
                }

                 //判断用户是否拥有具体的某个权限  isPermitted

               /* if(currentUser.isPermitted("洗脚权限")){
                    logger.info("您有资格洗脚");
                }else{
                    logger.info("你没资格洗脚，滚");
                }

                if(currentUser.isPermitted("piao娼权限")){
                    logger.info("您有资格piao");
                }else{
                    logger.info("你tM没有资格piao");
                }*/

                //退出登录 logout
                currentUser.logout();

            }catch (UnknownAccountException uae) {
                logger.info(token.getPrincipal() + "账户不存在");
            } catch (IncorrectCredentialsException ice) {
                logger.info(token.getPrincipal() + "密码不正确");
            } catch (LockedAccountException lae) {
                logger.info(token.getPrincipal() + "用户被锁定了 ");
            } catch (AuthenticationException ae) {
                //无法判断是什么错了
                logger.info(ae.getMessage());
            }


        }



    }
}

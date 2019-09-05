import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.realm.SimpleAccountRealm;
import org.apache.shiro.subject.Subject;
import org.junit.Before;
import org.junit.Test;

public class AuthenticationTest2 {
    //指定Realm
    SimpleAccountRealm simpleAccountRealm=new SimpleAccountRealm();
    @Before
    public void addUser(){
        //在Realm中添加用户，并将SimpleAccountRealm添加到SecurityManager环境中
        simpleAccountRealm.addAccount("Mark","123456","admin","user");
    }
    @Test
    public void authenticationTest(){
        //构建SecurityManager环境
        DefaultSecurityManager defaultSecurityManager=new DefaultSecurityManager();
        defaultSecurityManager.setRealm(simpleAccountRealm);
        //主体提交认证请求
        //获得主体
        SecurityUtils.setSecurityManager(defaultSecurityManager);
        Subject subject=SecurityUtils.getSubject();
        //登录提交认证
        //认证数据
        UsernamePasswordToken token=new UsernamePasswordToken("Mark","123456");

        subject.login(token);
        //采用shiro的认证方法进行认证
        System.out.println("是否认证："+subject.isAuthenticated());

        //验证授权
        subject.checkRoles("admin","user");


    }
}

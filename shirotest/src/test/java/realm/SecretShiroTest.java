package realm;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authc.credential.HashedCredentialsMatcher;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.subject.Subject;
import org.junit.Test;

public class SecretShiroTest {
    @Test
    public void authenticationTest(){
        CustomRealm customRealm=new CustomRealm();
        //构建SecurityManager环境
        DefaultSecurityManager defaultSecurityManager=new DefaultSecurityManager();
        defaultSecurityManager.setRealm(customRealm);

        //设置加密算法
        HashedCredentialsMatcher matcher=new HashedCredentialsMatcher();
        //设置加密名称
        matcher.setHashAlgorithmName("md5");
        //设置加密次数
        matcher.setHashIterations(1);
        //在自定义Realm中添加HashedCredentialsMatcher对象
        customRealm.setCredentialsMatcher(matcher);

        //主体提交认证请求
        //获得主体
        SecurityUtils.setSecurityManager(defaultSecurityManager);
        Subject subject=SecurityUtils.getSubject();
        //登录提交认证
        //认证数据
        UsernamePasswordToken token=new UsernamePasswordToken("zhangsan","654321");

        subject.login(token);
        //采用shiro的认证方法进行认证
        System.out.println("是否认证："+subject.isAuthenticated());

        //subject.checkRoles("admin","user");

        //subject.checkPermission("user:select");

    }
}

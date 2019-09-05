import com.alibaba.druid.pool.DruidDataSource;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.realm.jdbc.JdbcRealm;
import org.apache.shiro.realm.text.IniRealm;
import org.apache.shiro.subject.Subject;
import org.junit.Test;

public class JdbcRealmTest {
    //创建数据源
    DruidDataSource druidDataSource=new DruidDataSource();
    {
        druidDataSource.setUrl("jdbc:mysql://127.0.0.1:3306/news?useUnicode=true&characterEncoding=utf-8");
        druidDataSource.setUsername("root");
        druidDataSource.setPassword("root");
    }
    @Test
    public void authenticationTest(){
        JdbcRealm jdbcRealm=new JdbcRealm();
        jdbcRealm.setDataSource(druidDataSource);
        //设置jdbc权限开关   默认为false
        jdbcRealm.setPermissionsLookupEnabled(true);

        String sql="select password from uname where username=?";
        jdbcRealm.setAuthenticationQuery(sql);

        String role="select rolename from user_role where username=?";
        jdbcRealm.setUserRolesQuery(role);

        String permission="select permission from roles_permissions where rolename=?";
        jdbcRealm.setPermissionsQuery(permission);
        //构建SecurityManager环境
        DefaultSecurityManager defaultSecurityManager=new DefaultSecurityManager();
        defaultSecurityManager.setRealm(jdbcRealm);
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
        //角色认证
        subject.checkRole("admin");
        //权限认证
        subject.checkPermission("user:select");
    }
}


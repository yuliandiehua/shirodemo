package shiro;

import dao.UserDao;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.credential.HashedCredentialsMatcher;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.crypto.hash.Md5Hash;
import org.apache.shiro.crypto.hash.SimpleHash;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;
import org.springframework.beans.factory.annotation.Autowired;
import pojo.User;

public class MyRealm extends AuthorizingRealm {
    @Autowired
    private UserDao userDao;
    String pass;

    /**
     * 授权
     * @param principalCollection
     * @return
     */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        SimpleAuthorizationInfo info=new SimpleAuthorizationInfo();
        Object principal=principalCollection.getPrimaryPrincipal();//获取登录的用户名
        //两个if根据判断赋予登录用户权限
        if("admin".equals(principal)){
            info.addRole("admin");
        }
        if("user".equals(principal)){
            info.addRole("list");
        }
        info.addRole("user");
        return info;
    }

    /**
     * 用户验证
     * @param token
     * @return
     * @throws AuthenticationException
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        //1、token中获取登录的username！注意不要获取password.
        Object principal=token.getPrincipal();
        //2、利用username查询数据库得到用户的信息
        User user=userDao.findbyname((String) principal);
        if(user!=null){
            pass=user.getUserPassword();
        }
        String credentials=pass;
        //3、设置盐值（加密的调料，让加密出来的东西更具安全性，一般是通过数据库查询出来的。
        // 简单的说，就是把密码根据特定的东西而进行动态加密，如果别人不知道你的盐值，就解不出你的密码）
        String source="abcdefg";
        ByteSource credentialsSalt=new Md5Hash(source);
        //当前Realm的name
        String realmName=getName();
        //返回值实例化
        SimpleAuthenticationInfo info=new SimpleAuthenticationInfo(principal,credentials,credentialsSalt,realmName);
        return info;
    }
    //init-method配置
    public void setCredentialMatcher(){
        HashedCredentialsMatcher credentialsMatcher=new HashedCredentialsMatcher();
        credentialsMatcher.setHashAlgorithmName("MD5");//MD5算法加密
        credentialsMatcher.setHashIterations(1024);//1024次循环加密
        setCredentialsMatcher(credentialsMatcher);
    }
    //用来测试的算出密码password盐值加密后的结果，下面方法用于新增用户添加到数据库操作的，
    // 我这里就直接用main获得，直接数据库添加了，省时间
    public static void main(String[] args) {
        String saltSource="abcdef";
        String hashAlgorithmName="MD5";
        String credentials="passwor";
        Object salt=new Md5Hash(saltSource);
        int hashItertions=1024;
        Object result=new SimpleHash(hashAlgorithmName,credentials,salt,hashItertions);
        System.out.println(result);
    }
}

package realm;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.crypto.hash.Md5Hash;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * 自定义Realm
 */
public class CustomRealm extends AuthorizingRealm {
    Map<String,Object> userMap=new HashMap();
    {
        ///userMap.put("zhangsan","654321");
        //加密
        //userMap.put("zhangsan","c33367701511b4f6020ec61ded352059");
        //加密加盐
        userMap.put("zhangsan","83d303ea1ac9661885621082e6136f86");

        //设置Realm名称
        super.setName("customRealm");
    }
    //重写授权方法
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        //通过主体认证信息传过来的数据，获取其中的用户名称
        String username = (String) principalCollection.getPrimaryPrincipal();
        //从数据库获取用户角色数据
        Set<String> role=getRoleByUserName(username);
        //从数据库获取角色权限数据
        Set<String> permission=getPermissionByUserName(username);
        SimpleAuthorizationInfo simpleAuthorizationInfo=new SimpleAuthorizationInfo();
        //传入角色
        simpleAuthorizationInfo.setRoles(role);
        //传入权限
        simpleAuthorizationInfo.setStringPermissions(permission);
        return simpleAuthorizationInfo;
}

    private Set<String> getPermissionByUserName(String username) {
        Set<String> sets=new HashSet<>();
        sets.add("user:select");
        sets.add("user:update");
        return sets;
    }

    //操作数据库获取用户角色
    private Set<String> getRoleByUserName(String username) {
        Set<String> sets=new HashSet<>();
        sets.add("admin");
        sets.add("user");
        return sets;
    }

    //重写认证方法
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        //通过主体认证信息传过来的数据，获取其中的用户名称
        String username = (String) authenticationToken.getPrincipal();
        //通过用户名到数据库获取凭证（密码）
        String password=getPasswordByUserName(username);
        if(password==null){
            return null;
        }
        //不为空返回对象
        SimpleAuthenticationInfo simpleAuthenticationInfo=new SimpleAuthenticationInfo("zhangsan",password,"customRealm");
        //加盐
        simpleAuthenticationInfo.setCredentialsSalt(ByteSource.Util.bytes("hahaha"));
        return simpleAuthenticationInfo;
    }
    //操作数据库查询数据
    private String getPasswordByUserName(String username) {
        return (String) userMap.get(username);
    }
    //加密
    /*public static void main(String[] args) {
        Md5Hash md5Hash=new Md5Hash("654321");
        System.out.println(md5Hash.toString());
    }*/
    //加密加盐
    public static void main(String[] args) {
        Md5Hash md5Hash=new Md5Hash("123456");
        System.out.println(md5Hash.toString());
    }
}

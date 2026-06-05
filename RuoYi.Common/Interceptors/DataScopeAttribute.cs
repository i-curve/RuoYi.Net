using AspectCore.DynamicProxy;
using RuoYi.Common.Constants;
using RuoYi.Common.Utils;
using RuoYi.Data;
using RuoYi.Data.Dtos;
using RuoYi.Data.Models;
using RuoYi.Framework;
using RuoYi.Framework.Extensions;
using RuoYi.Framework.Logging;
using RuoYi.Framework.Utils;
using SqlSugar;
using StackExchange.Redis;
using System.Text;

namespace RuoYi.Common.Interceptors
{
    // https://github.com/dotnetcore/AspectCore-Framework/blob/master/docs/1.%E4%BD%BF%E7%94%A8%E6%8C%87%E5%8D%97.md
    // https://www.cnblogs.com/twinhead/p/9229062.html
    // 在要被拦截的方法上标注 DataScopeAttribute, 类需要是public类，方法如果需要拦截就是[虚方法]，支持异步方法，因为动态代理是动态生成被代理的类的动态子类实现的。
    public class DataScopeAttribute : AbstractInterceptorAttribute
    {
        // 部门表的别名
        public string? DeptAlias { get; set; }
        // 用户表的别名
        public string? UserAlias { get; set; }

        // 部门字段名
        public string? DeptField { get; set; } = "dept_id";
        // 用户字段名
        public string? UserField { get; set; } = "user_id";

        // 权限字符（用于多个角色匹配符合要求的权限），多个权限用逗号分隔开来
        public string? Permission { get; set; }

        public async override Task Invoke(AspectContext context, AspectDelegate next)
        {
            try
            {
                Console.WriteLine("Before service call");

                // 获取当前的用户
                LoginUser loginUser = SecurityUtils.GetLoginUser();
                if (loginUser != null)
                {
                    SysUserDto currentUser = loginUser.User;
                    // 如果是超级管理员，则不过滤数据
                    if (currentUser != null && !SecurityUtils.IsAdmin(currentUser))
                    {
                        string permission = StringUtils.DefaultIfEmpty(Permission, PermissionContextHolder.GetContext());
                        this.DataScopeFilter(context, currentUser, DeptAlias, UserAlias, DeptField, UserField, permission);
                    }
                }

                await next(context);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Service threw an exception!");
                Log.Error("DataScope Error", ex);
                //throw;
            }
            finally
            {
                Console.WriteLine("After service call");
            }
        }

        /// <summary>
        /// 数据范围过滤
        /// </summary>
        /// <param name="context">切点</param>
        /// <param name="user">用户</param>
        /// <param name="deptAlias">部门别名</param>
        /// <param name="userAlias">用户别名</param>
        /// <param name="userField">自定义用户字段</param>
        /// <param name="deptField">自定义部门字段</param>
        /// <param name="permission">权限字符</param>
        private void DataScopeFilter(AspectContext context, SysUserDto user, string deptAlias, string userAlias, String userField, String deptField, string permission)
        {
            DbType dbType = this.getDbType();

            StringBuilder sqlString = new StringBuilder();
            List<string> conditions = new List<string>();
            List<long> scopeCustomIds = user.Roles
                .Where(r => DataScope.Custom == r.DataScope && Status.Enabled == r.Status
                    && (String.IsNullOrEmpty(permission) || StringUtils.ContainsAny(r.Permissions, permission.Split(",")))
                ).Select(r => r.RoleId)
                .ToList();

            foreach (SysRoleDto role in user.Roles ?? new List<SysRoleDto>())
            {
                var dataScope = role.DataScope ?? DataScope.Custom;
                if (conditions.Contains(dataScope) || Status.Disabled == role.Status)
                {
                    continue;
                }
                if (StringUtils.IsNotEmpty(permission) && role.Permissions.IsNotEmpty() && !StringUtils.ContainsAny(role.Permissions, permission))
                {
                    continue;
                }
                if (DataScope.All == dataScope)
                {
                    sqlString = new StringBuilder();
                    conditions.Add(dataScope);
                    break;
                }
                else if (DataScope.Custom.Equals(dataScope))
                {
                    if (scopeCustomIds.Count > 0)
                    {
                        sqlString.Append($" OR {deptAlias}.{deptField} IN ( SELECT dept_id FROM sys_role_dept WHERE role_id IN ({string.Join(",", scopeCustomIds)}) ) ");
                    }
                    else
                    {
                        sqlString.Append($" OR {deptAlias}.{deptField} IN ( SELECT dept_id FROM sys_role_dept WHERE role_id = ({role.RoleId}) ) ");
                    }
                }
                else if (DataScope.Department.Equals(dataScope))
                {
                    sqlString.Append($" OR {deptAlias}.{deptField} = {user.DeptId} ");
                }
                else if (DataScope.DepartmentAndChild.Equals(dataScope))
                {
                    if (dbType == DbType.SqlServer)
                    {
                        sqlString.Append($" OR {deptAlias}.{deptField} IN ( SELECT dept_id FROM sys_dept WHERE dept_id = {user.DeptId} or CHARINDEX(',{user.DeptId},', ',' + ancestors + ',' ) > 0 )");
                    }
                    else
                    {
                        sqlString.Append($" OR {deptAlias}.{deptField} IN ( SELECT dept_id FROM sys_dept WHERE dept_id = {user.DeptId} or find_in_set( {user.DeptId} , ancestors ) )");
                    }
                }
                else if (DataScope.Self.Equals(dataScope))
                {
                    if (StringUtils.IsNotBlank(userAlias))
                    {
                        sqlString.Append($" OR {userAlias}.{userField} = {user.UserId} ");
                    }
                    else
                    {
                        // 数据权限为仅本人且没有userAlias别名不查询任何数据
                        sqlString.Append($" OR {deptAlias}.{deptField} = 0 ");
                    }
                }
                conditions.Add(dataScope);
            }

            // 多角色情况下，所有角色都不包含传递过来的权限字符，这个时候sqlString也会为空，所以要限制一下,不查询任何数据
            if (conditions.IsEmpty())
            {
                sqlString.Append($" OR {deptAlias}.{deptField} = 0 ");
            }

            if (StringUtils.IsNotBlank(sqlString.ToString()))
            {
                object parameters = context.Parameters[0];
                if (parameters != null && parameters.GetType().BaseType != null && parameters.GetType().BaseType!.Equals(typeof(BaseDto)))
                {
                    BaseDto baseEntity = (BaseDto)parameters;
                    baseEntity.Params.DataScopeSql = $" ({sqlString.ToString()[4..]})";
                }
            }
        }

        private DbType getDbType()
        {
            var connectionConfigs = App.GetConfig<ConnectionConfig[]>("ConnectionConfigs");
            if (connectionConfigs != null && connectionConfigs.Length > 0)
            {
                return connectionConfigs[0].DbType;
            }

            return DbType.MySql;
        }
    }
}

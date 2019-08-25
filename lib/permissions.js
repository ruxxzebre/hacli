/**
 * The default roles and role hierarchy if a custom one isn't passed in
 */

// The default roles
//const PermissionTypes = {
//  SUPER_ADMIN: 'SUPER_ADMIN',
//  ADMIN: 'ADMIN',
//  USER: 'USER',
//  GUEST: 'GUEST'
//};

const SUPER_ADMIN = 'SUPER_ADMIN';
const ADMIN       = 'ADMIN';
const USER        = 'USER';
const GUEST       = 'GUEST';

// The default roles and hierarchy
const Permissions     = [SUPER_ADMIN, ADMIN, USER, GUEST];

// The default role hierarchy
//const PermissionHierarchy = [];
//PermissionHierarchy.SUPER_ADMIN	= [SUPER_ADMIN, ADMIN, USER, GUEST];
//PermissionHierarchy.ADMIN				= [ADMIN, USER, GUEST];
//PermissionHierarchy.USER				= [USER, GUEST];
//PermissionHierarchy.GUEST				= [GUEST];

module.exports = {
  Permissions
};

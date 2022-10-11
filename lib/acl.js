// External modules
const Boom	= require('boom');
const { has } = require("./utilities");

// Declare of internals
const internals = {};


/**
 * Checks if the user has the wanted permissions
 *
 * @param user	- The user to check if they have a permission
 * @param permission	- The permission to check if the user has
 * @returns {*}
 */
exports.checkPermissions = function(user, permission, permissions) {

  if ((!user) || (!internals.isGranted(user.permission || user.permissions, permission, permissions))) {
    return Boom.forbidden('Unauthorized');
  }

  return null;
};

internals.findInObj = function(obj, key) {
  if (has(obj, key)) {
    return obj[key];
  } else {
    for (let k in obj) {
      const res =  internals.findInObj(obj[k], key);
      if (res) {
        return res;
      }
    }
  }

  return false;
}

/**
 * Checks if the provided user permission is included is the required permission or is included in the required permission permissions
 *
 * @param userPermission			- The permission(s) that the user has
 * @param requiredPermission	- The permission(s) that is required
 * @returns {boolean}		- True/False whether the user has access
 */
internals.isGranted = function(userPermission, requiredPermission, permissions) {
  let requiredPermissions = [];
  let userPermissions;

  // If the user has no permissions
  if(!userPermission) {
    return false;
  }

  // If the requiredPermission is an array
  if(Array.isArray(requiredPermission)) {
    requiredPermissions = requiredPermission;
  } else {
    requiredPermissions = [requiredPermission];
  }

  // If the userPermission is an array
  if(Array.isArray(userPermission)) {
    userPermissions = userPermission;
  } else {
    userPermissions = [userPermission];
  }

  // If we're using a permissions, get all the possible permissions
  if(!Array.isArray(permissions)) {
    for (let _userPermission of userPermissions) {
      if (requiredPermissions.indexOf(_userPermission) !== -1) {
        return true;
      }
      const userPermissionAcl = internals.findInObj(permissions, _userPermission)
      if (userPermissionAcl) {
        for (let _requiredPermission of requiredPermissions) {
          if (internals.findInObj(userPermissionAcl, _requiredPermission)) {
            return true;
          }
        }
      }
    }
  } else {
    for (let _userPermission of userPermissions) {
      if (requiredPermissions.indexOf(_userPermission) !== -1) {
        return true;
      }
    }
  }

  return false;
};

/**
 * Fetches the wanted acl entity using the provided
 *
 * @param query - function(id, cb) that returns the entity to the callback.
 * @param param - The "id" parameter that need to be provided for to the query
 * @param request - The originating request
 * @return wanted ACL entity
 */
exports.fetchEntity = async (query, param, request) => {
  try {
    const entity = await query(param, request);
    if (!entity) {
      throw Boom.notFound();
    }
    return entity;
  } catch (err) {
    if (err.isBoom) {
      throw err;
    } else if (err) {
      throw Boom.badRequest('Bad Request', err);
    }
  }
};


/**
 * Verifies that the user has permission to access the wanted entity.
 *
 * @param user - The authenticated user
 * @param permission - The wanted permission, undefined means any permission
 * @param entity - Verify if the authenticated user has "permission" grants and can access this entity
 * @param validator - The method that will be used to verify if the user has permissions, this method should be used on the provided entity.
 * @param options - additional options
 * @returns {boolean} Validation check result
 */
exports.validateEntityAcl = async (user, permission, entity, validator, options) => {
  if (!entity) {
    throw new Error('validateUserACL must run after fetchACLEntity');
  } else if (!user) {
    throw new Error('User is required, please make sure this method requires authentication');
  } else {
    if (validator) {

      try {
        const isValid = await entity[validator](user, permission);

        if (!isValid) {	// Not granted
          throw Boom.forbidden('Unauthorized');
        } else {	// Valid
          return isValid;
        }
      } catch (err) {
        if (err.isBoom) {
          throw err;
        } else {
          throw new Error(err);
        }
      }
    } else {
      // Use the default validator
      const isValid = internals.defaultEntityAclValidator(user, permission, entity, options);
      if (isValid) {
        return isValid;
      } else {
        throw Boom.forbidden('Unauthorized');
      }
    }
  }
};

/**
 * Default validator
 *
 * @param user
 * @param permission
 * @param entity
 * @param options
 * @returns {*|string|boolean}
 */
internals.defaultEntityAclValidator = function(user, permission, entity, options) {
  return (
    entity[options.entityUserField] &&
    user[options.userIdField] &&
    entity[options.entityUserField].toString() === user[options.userIdField].toString()
  );
};

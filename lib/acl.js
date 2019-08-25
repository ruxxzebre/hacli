// External modules
const Boom	= require('boom');
const _			= require('underscore');

// Declare of internals
const internals = {};


/**
 * Checks if the user has the wanted roles
 *
 * @param user	- The user to check if they have a role
 * @param role	- The role to check if the user has
 * @returns {*}
 */
exports.checkRoles = function(user, role, permissions) {

	if ((!user) || (!internals.isGranted(user.role, role, permissions))) {
		return Boom.forbidden('Unauthorized');
	}

	return null;
};

internals.findInObj = function(obj, key) {
  if (_.has(obj, key)) {
    return obj[key];
  } else {
    for (let k in obj) {
      const res =  internals.findInObj(obj[k], k);
      if (res) {
        return res;
      }
    }
  }

  return false;
}

/**
 * Checks if the provided user role is included is the required role or is included in the required role permissions
 *
 * @param userPermission			- The role(s) that the user has
 * @param requiredPermission	- The role(s) that is required
 * @returns {boolean}		- True/False whether the user has access
 */
internals.isGranted = function(userPermission, requiredPermission, permissions) {
  let requiredPermissions = [];
  let userPermissions;

  // If the user has no roles
  if(!userPermission) {
    return false;
  }

  // If the requiredPermission is an array
	if(_.isArray(requiredPermission)) {
    requiredPermissions = requiredPermission;
  } else {
	  requiredPermissions = [requiredPermission];
	}

  // If the userPermission is an array
  if(_.isArray(userPermissions)) {
    userPermissions = userPermission;
  } else {
    userPermissions = [userPermission];
  }

  // If we're using a permissions, get all the possible roles
  if(!_.isArray(permissions)) {
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
 * @param role - The wanted role, undefined means any role
 * @param entity - Verify if the authenticated user has "role" grants and can access this entity
 * @param validator - The method that will be used to verify if the user has permissions, this method should be used on the provided entity.
 * @param options - additional options
 * @returns {boolean} Validation check result
 */
exports.validateEntityAcl = async (user, role, entity, validator, options) => {
  if (!entity) {
    throw new Error('validateUserACL must run after fetchACLEntity');
  } else if (!user) {
    throw new Error('User is required, please make sure this method requires authentication');
  } else {
    if (validator) {

      try {
        const isValid = await entity[validator](user, role);

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
      const isValid = internals.defaultEntityAclValidator(user, role, entity, options);
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
 * @param role
 * @param entity
 * @param options
 * @returns {*|string|boolean}
 */
internals.defaultEntityAclValidator = function(user, role, entity, options) {
	return (
	entity[options.entityUserField] &&
	user[options.userIdField] &&
	entity[options.entityUserField].toString() === user[options.userIdField].toString()
	);
};

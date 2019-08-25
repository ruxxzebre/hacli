# hacli

*hacli only supports hapi 17+*

> ACL support for hapijs apps based on permissions hierarchy

[![npm version][npm-badge]][npm-url]
[![Build Status][travis-badge]][travis-url]
[![Coverage Status][coveralls-badge]][coveralls-url]

You can use this plugin to add ACL and protect your routes. You can configure required permissions and allow access to certain endpoints only to specific users or to users having that specific permission.

# Installation

```npm i @antoniogiordano/hacli -S```

# Usage

**Note**: To use hacli you must have an authentication strategy defined.

There are 2 ways to use hacli:

1. With the default permissions which are: "SUPER_ADMIN", "ADMIN", "USER", "GUEST"
2. By defining your own permissions

## Using hacli with default permissions
1. Include the plugin in your hapijs app.
Example:
```js
let plugins = [
	{
		plugin: require('hapi-auth-basic')
	},
	{
		plugin: require('@antoniogiordano/hacli'),
		options: {}
	}
];

await server.register(plugins);
```

## Using hacli with a list of permissions
1. Include the plugin in your hapijs app.
Example:
```js
let plugins = [
	{
		plugin: require('hapi-auth-basic')
	},
	{
		plugin: require('@antoniogiordano/hacli'),
		options: {
			permissions: ['CAN_CREATE_RESOURCE', 'CAN_EDIT_RESOURCE', 'CAN_DELETE_RESOURCE']
		}
	}
];

await server.register(plugins);
```

## Using hacli with an hierarchy of permissions
1. Include the plugin in your hapijs app.
Example:
```js
let plugins = [
	{
		plugin: require('hapi-auth-basic')
	},
	{
		plugin: require('@antoniogiordano/hacli'),
		options: {
			permissions: {
			  SUPERADMIN: {
			    ADMIN: {
                  CAN_EDIT_RESOURCE: {},
                  CAN_DELETE_RESOURCE: {},
                  USER: {
			        CAN_CREATE_RESOURCE: {},
                  }               
                }               
              }                   
            }
		}
	}
];

await server.register(plugins);
```

## permissions option
hacli behaviour is based on the ``permissions`` option type passed during plugin configuration, that can be an array or an object.
If ``permissions`` is an array, then the order of the permissions string has NO hierarchy effect, and every permission will be treated separately.
Instead, if you pass an object as a ``permissions`` option, that you can nest the permissions in an hierarchy form, where all the keys nested inside an other one, are included in that.
In the previous example, a user with a SUPERADMIN permission, can actually access ALL the other permissions, because they are all nested inside it. In the same way, a user with USER permission, can access all the routes with both USER and CAN_CREATE_RESOURCE permissions.

## Full Examples using hapi-auth-basic and hacli

### permissions array
```js
const Hapi = require('hapi');

// Instantiate the server
let server = new Hapi.Server();

/**
 * The hapijs plugins that we want to use and their configs
 */
let plugins = [
	{
		register: require('hapi-auth-basic')
	},
	{
		register: require('@antoniogiordano/hacli'),
		options: {
			permissions: ['OWNER', 'MANAGER', 'EMPLOYEE']
		}
	}
];

let validate = (username, password) => {
	// Perform authentication and respond with object that contains a permission or an array of permissions
	return {username: username, permission: 'EMPLOYEE'};
}

/**
 * Setup the server with plugins
 */
await server.register(plugins);
server.start().then(() => {

	server.auth.strategy('simple', 'basic', {validateFunc: validate});
	server.auth.default('simple');
  
    server.route({
     method: 'GET',
     path: '/getEmployeesList',
     config: {
       handler: () => null, // some handler function
       plugins: {
         hacli: {
           permissions: 'OWNER'
         }
       }
     }
    })
    // Our user with EMPLOYEE permission can NOT access this!

    server.route({
     method: 'GET',
     path: '/getReport',
     config: {
       handler: () => null, // some handler function
       plugins: {
         hacli: {
           permissions: 'EMPLOYEE'
         }
       }
     }
    })
    // Our user with EMPLOYEE permission can access this!

	/**
	 * Starts the server
	 */
	server.start()
        .then(() => {
            console.log('Hapi server started @', server.info.uri);
        })
        .catch((err) => {
            console.log(err);
        });
})
.catch((err) => {
  // If there is an error on server startup
  throw err;
});
```

### permissions hierarchy object
```js
const Hapi = require('hapi');

// Instantiate the server
let server = new Hapi.Server();

/**
 * The hapijs plugins that we want to use and their configs
 */
let plugins = [
	{
		register: require('hapi-auth-basic')
	},
	{
		register: require('@antoniogiordano/hacli'),
		options: {
            permissions: {
              SUPERADMIN: {
                CAN_CREATE_ADMIN: {},
                CAN_LIST_ADMINS: {},
                CAN_VIEW_FULL_REPORT: {},
                ADMIN: {
                  CAN_EDIT_RESOURCE: {},
                  CAN_DELETE_RESOURCE: {},
                  USER: {
                    CAN_CREATE_RESOURCE: {},
                  }               
                }               
              }                   
            }
		}
	}
];

let validate = (username, password) => {
	// Perform authentication and respond with object that contains a permission or an array of permissions
	return {username: username, permissions: ['ADMIN', 'CAN_VIEW_FULL_REPORT']};
}

/**
 * Setup the server with plugins
 */
await server.register(plugins);
server.start().then(() => {

	server.auth.strategy('simple', 'basic', {validateFunc: validate});
	server.auth.default('simple');
  
    server.route({
     method: 'GET',
     path: '/listAdmins',
     config: {
       handler: () => null, // some handler function
       plugins: {
         hacli: {
           permissions: 'CAN_LIST_ADMINS'
         }
       }
     }
    })
    // Our user with ['ADMIN', 'CAN_VIEW_FULL_REPORT'] permissions can NOT access this!

    server.route({
     method: 'GET',
     path: '/getAdminProfile',
     config: {
       handler: () => null, // some handler function
       plugins: {
         hacli: {
           permissions: 'ADMIN'
         }
       }
     }
    })
    // Our user with ['ADMIN', 'CAN_VIEW_FULL_REPORT'] permissions can access this!

    server.route({
     method: 'GET',
     path: '/getAdminProfile',
     config: {
       handler: () => null, // some handler function
       plugins: {
         hacli: {
           permissions: 'ADMIN'
         }
       }
     }
    })
    // Our user with ['ADMIN', 'CAN_VIEW_FULL_REPORT'] permissions can access this!

    server.route({
     method: 'POST',
     path: '/createResource',
     config: {
       handler: () => null, // some handler function
       plugins: {
         hacli: {
           permissions: 'CAN_CREATE_RESOURCE'
         }
       }
     }
    })
    // Our user with ['ADMIN', 'CAN_VIEW_FULL_REPORT'] permissions can access this!

	/**
	 * Starts the server
	 */
	server.start()
        .then(() => {
            console.log('Hapi server started @', server.info.uri);
        })
        .catch((err) => {
            console.log(err);
        });
})
.catch((err) => {
  // If there is an error on server startup
  throw err;
});
```

#### Whitelist Routes That Require Authorization
If you want no routes require authorization except for the ones you specify in the route config, add hacli instructions with the permission(s) that should have access to the route configuration.

Example:

**Authorize a single permission**
```js
server.route({ method: 'GET', path: '/', options: {
  plugins: {'hacli': {permission: 'ADMIN'}},	// Only ADMIN permission
  handler: (request, h) => { return "Great!"; }
}});
```

**Authorize multiple permissions**
```js
server.route({ method: 'GET', path: '/', options: {
  plugins: {'hacli': {permissions: ['USER', 'ADMIN']}},
  handler: (request, h) => { return "Great!"; }
}});
```

#### Blacklist All Routes To Require Authorization

If you want all routes to require authorization except for the ones you specify that should not, add hacli instructions with the permission(s) that should have access to the server.connection options. Note that these can be overridden on each route individually as well.

Example:

```js
let server = new Hapi.server({
	routes: {
		plugins: {
			hacli: { permissions: ['ADMIN'] }
		}
	}
});
```

**Override the authorization to require alternate permissions**
```js
server.route({ method: 'GET', path: '/', options: {
  plugins: {'hacli': {permission: 'USER'}},	// Only USER permission
  handler: (request, h) => { return "Great!" ;}
}});
```

**Override the authorization to not require any authorization**
```js
server.route({ method: 'GET', path: '/', options: {
  plugins: {'hacli': false},
  handler: (request, h) => { return "Great!"; }
}});
```

**Note:** Every route that uses hacli must be protected by an authentication schema either via `auth.strategy.default('someAuthStrategy')` or by specifying the auth on the route itself.

## Gotchas

### Auth before routes
You must define your auth strategy before defining your routes, otherwise the route validation will fail.


## Plugin Config

* `permissions` 				- `Array|Object`: All the possible permissions. Defaults to permissions list [`SUPER_ADMIN`, `ADMIN`, `USER`, `GUEST`]. Can be an hierarchy object where every key is a permission, and can or not contain other permission keys. The "leaves" of the object (permission keys without sub-permissions) should any way be empty object.
* `userPath` 				    - `String`: Where hacli should look for user object inside the request object. Defaults to "auth.credentials", that resolves to request.auth.credentials.user. 



## Route config of supported parameters:
* `permission` - `String`: enforces that only users that have this permission can access the route
* `permissions` - `Array`: enforces that only users that have at least one of these permissions can access the route
* `aclQuery` - `Function`: fetches an entity using the provided query, it allows the plugin to verify that the authenticated user has permissions to access this entity. the function signature should be `function(parameter, request)`.
* `aclQueryParam` - `String`: The parameter key that will be used to fetch the entity. default: 'id'
* `paramSource` - `String`: The source of the acl parameter, allowed values: payload, params, query.
* `validateEntityAcl` - `Boolean`: Should the plugin validate if the user has access to the entity. if true, validateAclMethod is required.
* `validateAclMethod` - `String`: A function name. the plugin will invoke this method on the provided entity and will use it to verify that the user has permissions to access this entity. function signature is `function(user, permission)`;


[npm-badge]: https://badge.fury.io/js/%40antoniogiordano%2Fhacli.svg
[npm-url]: https://www.npmjs.com/package/@antoniogiordano/hacli
[travis-badge]: https://travis-ci.org/antoniogiordano/hacli.svg?branch=master
[travis-url]: https://travis-ci.org/antoniogiordano/hacli
[coveralls-badge]: https://coveralls.io/repos/antoniogiordano/hacli/badge.svg?branch=master&service=github
[coveralls-url]:  https://coveralls.io/github/antoniogiordano/hacli?branch=master

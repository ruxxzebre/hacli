// External modules
const expect = require('chai').expect;
const Hapi = require('hapi');
const Joi = require('@hapi/joi');

// Internal modules
const libpath = process.env['HAPI_AUTHORIZATION_COV'] ? '../lib-cov' : '../lib';
const Plugin = require(libpath + '/index');

// Declare internals
const internals = {};

function NOOP(){}

describe('hacli', () => {
	const plugin = {
		name: 'hacli',
		version: '0.0.0',
		register: Plugin.plugin.register,
		path: libpath
	};

	it('does not interfere with handlers throwing exceptions', async (done) => {
		const server = new Hapi.Server();
		server.route({ method: 'GET', path: '/', options: {
			handler: function (request, h) {return new Error("uncaught exception test");}
		}});
    await server.register(plugin, {});

    server.start().then(() => {
      server.inject({method: 'GET', url: '/'}).then((res) => {
        internals.asyncCheck(() => {
          expect(res.statusCode).to.equal(500);
          server.stop(NOOP);
        }, done);
      });
    });
	});

	it('makes sure that hacli can be enabled only for secured routes', (done) => {
		const server = new Hapi.Server();
		server.route({ method: 'GET', path: '/', options: {
			plugins: {'hacli': {permission: 'USER'}},
			handler: (request, h) => { return "TEST";}
		}});
		server.register(plugin, {}).then(() => {
			server.start().catch((err) => {
				expect(err).to.not.be.undefined;
				expect(err).to.match(/hacli can be enabled only for secured route/);
				server.stop(NOOP); // Make sure the server is stopped
				done();
			});
		});
	});

	it('should allow hacli for routes secured in the route config', (done) => {
		const server = new Hapi.Server();

		server.auth.scheme('custom', internals.authSchema);
		server.auth.strategy('default', 'custom', {});
		server.route({ method: 'GET', path: '/', options: {
			auth: 'default',
			plugins: {'hacli': {permission: 'USER'}},
			handler: (request, h) => { return "TEST";}
		}});
		server.register(plugin, {}).then(() => {
			server.start().then(() => {
				server.stop(NOOP); // Make sure the server is stopped
				done();
			});
		});
	});

	it('should allow hacli for routes secured globally with authentication', (done) => {
		const server = new Hapi.Server();

		server.auth.scheme('custom', internals.authSchema);
		server.auth.strategy('default', 'custom', {});
		server.auth.default('default');
		server.route({ method: 'GET', path: '/', options: {
			plugins: {'hacli': {permission: 'USER'}},
			handler: (request, h) => { return "TEST";}
		}});
		server.register(plugin, {}).then(() => {
			server.start().then(() => {
				server.stop(NOOP); // Make sure the server is stopped
				done();
			});
		});
	});

	it('should allow hacli for routes secured globally with authentication and blacklisting routes to require authorization', (done) => {
		const server = new Hapi.Server({
			routes: {
				plugins: {
					hacli: { permissions: ['USER'] }
				}
			}
		});
		server.auth.scheme('custom', internals.authSchema);
		server.auth.strategy('default', 'custom', {});
		server.auth.default('default');
		server.route({ method: 'GET', path: '/', options: {
			//plugins: {'hacli': {permission: 'USER'}},
			handler: (request, h) => { return "TEST";}
		}});
		server.register(plugin, {}).then(() => {
			server.start().then(() => {
				server.stop(NOOP); // Make sure the server is stopped
				done();
			});
		});
	});

	it('should error with global authentication not set and blacklisting routes to require authorization', (done) => {
		const server = new Hapi.Server({
			routes: {
				plugins: {
					hacli: { permissions: ['USER'] }
				}
			}
		});
		//server.auth.scheme('custom', internals.authSchema);
		//server.auth.strategy('default', 'custom', {});
		//server.auth.default('default');
		server.route({ method: 'GET', path: '/', options: {
			//plugins: {'hacli': {permission: 'USER'}},
			handler: (request, h) => { return "TEST";}
		}});
		server.register(plugin, {}).then(() => {
			server.start().catch((err) => {
				expect(err).to.not.be.undefined;
				expect(err).to.match(/hacli can be enabled only for secured route/);
				server.stop(NOOP); // Make sure the server is stopped
				done();
			});
		});
	});

	it('should error with global auth set but auth false on route', (done) => {
		const server = new Hapi.Server();

		server.auth.scheme('custom', internals.authSchema);
		server.auth.strategy('default', 'custom', {});
		server.auth.default('default');
		server.route({ method: 'GET', path: '/', options: {
			auth: false,
			plugins: {'hacli': {permission: 'USER'}},
			handler: (request, h) => { return "TEST";}
		}});
		server.register(plugin, {}).then(() => {
			server.start().catch((err) => {
				expect(err).to.not.be.undefined;
				server.stop(NOOP); // Make sure the server is stopped
				done();
			});
		});
	});

	it('Validates the hacli routes parameters', (done) => {
		const server = new Hapi.Server();

		server.auth.scheme('custom', internals.authSchema);
		server.auth.strategy('default', 'custom', {});
		server.route({ method: 'GET', path: '/', options: {
			auth: 'default',
			plugins: {'hacli': {bla: 'USER'}},
			handler: (request, h) => { return "TEST";}
		}});
		server.register(plugin, {}).then(() => {
			server.start().catch((err) => {
				expect(err).to.not.be.undefined;
				expect(err).to.match(/"bla" is not allowed/);
				server.stop(NOOP); // Make sure the server is stopped
				done();
			});
		});
	});

	it('ignores routes without hacli instructions', (done) => {
		const server = new Hapi.Server();

		server.route({ method: 'GET', path: '/', handler: (request, h) => { return "TEST"; } });
		server.register(plugin, {}).then(() => {

			server.inject('/').then((res) => {

				expect(res.payload).to.equal("TEST");
				done();
			});
		});
	});

	it('Validates the hacli plugin options do not contain random options', (done) => {
		const server = new Hapi.Server();

		server.auth.scheme('custom', internals.authSchema);
		server.auth.strategy('default', 'custom', {});
		server.route({ method: 'GET', path: '/', options: {
			auth: 'default',
			plugins: {'hacli': {bla: 'USER'}},
			handler: (request, h) => { return "TEST";}
		}});

		const plugin = {
			name: 'hacli',
			version: '0.0.0',
			plugin: Plugin.plugin,
			path: libpath,
			options: {
				foo: 'TEST',
				permissions: ['EMPLOYEE', 'OWNER', 'MANAGER']
			}
		};

		server.register(plugin, {}).catch((err) => {
			expect(err).to.not.be.undefined;
			expect(err).to.be.instanceOf(Error);
			expect(err.message).to.equal('Invalid plugin options (Invalid settings) ValidationError: "foo" is not allowed');
			done();
		});
	});

	it('Validates the hacli plugin option "permissions" can be an array', (done) => {
		const server = new Hapi.Server();

		server.auth.scheme('custom', internals.authSchema);
		server.auth.strategy('default', 'custom', {});
		server.route({ method: 'GET', path: '/', options: {
			auth: 'default',
			plugins: {'hacli': {bla: 'USER'}},
			handler: (request, h) => { return "TEST";}
		}});

		const plugin = {
			name: 'hacli',
			version: '0.0.0',
			plugin: Plugin.plugin,
			path: libpath,
			options: {
				permissions: 'TEST'
			}
		};

		server.register(plugin, {}).catch((err) => {
			expect(err).to.not.be.undefined;
			expect(err).to.be.instanceOf(Error);
			expect(err.message).to.equal('Invalid plugin options (Invalid settings) ValidationError: "permissions" must be an array "permissions" must be an object');
			done();
		});
	});

	it('Validates the hacli plugin option "permissions" should be in an ACL format', (done) => {
		const server = new Hapi.Server();

		server.auth.scheme('custom', internals.authSchema);
		server.auth.strategy('default', 'custom', {});
		server.route({ method: 'GET', path: '/', options: {
				auth: 'default',
				plugins: {'hacli': {bla: 'USER'}},
				handler: (request, h) => { return "TEST";}
			}});

		const plugin = {
			name: 'hacli',
			version: '0.0.0',
			plugin: Plugin.plugin,
			path: libpath,
			options: {
				permissions: {
					OWNER: {
						USER: {},
						EMPLOYEE: 1
					}
				}
			}
		};

		server.register(plugin, {}).catch((err) => {
			expect(err).to.not.be.undefined;
			expect(err).to.be.instanceOf(Error);
			expect(err.message).to.equal('Invalid plugin options (Invalid settings) EMPLOYEE in permissions hierarchy object should be an object');
			done();
		});
	});

	it('Validates the hacli plugin option "userPath" must be a string', (done) => {
		const server = new Hapi.Server();

		server.auth.scheme('custom', internals.authSchema);
		server.auth.strategy('default', 'custom', {});
		server.route({ method: 'GET', path: '/', options: {
				auth: 'default',
				plugins: {'hacli': {bla: 'USER'}},
				handler: (request, h) => { return "TEST";}
			}});

		const plugin = {
			name: 'hacli',
			version: '0.0.0',
			plugin: Plugin.plugin,
			path: libpath,
			options: {
				permissions: ['OWNER', 'MANAGER', 'EMPLOYEE'],
				userPath: 120
			}
		};

		server.register(plugin, {}).catch((err) => {
			expect(err).to.not.be.undefined;
			expect(err).to.be.instanceOf(Error);
			expect(err.message).to.equal('Invalid plugin options (Invalid settings) ValidationError: "userPath" must be a string');
			done();
		});
	});

	it('Validates the hacli plugin options are optional', (done) => {
		const server = new Hapi.Server();

		server.auth.scheme('custom', internals.authSchema);
		server.auth.strategy('default', 'custom', {});
		server.route({ method: 'GET', path: '/', options: {
			auth: 'default',
			plugins: {'hacli': {bla: 'USER'}},
			handler: (request, h) => { return "TEST";}
		}});

		const plugin = {
			name: 'hacli',
			version: '0.0.0',
			plugin: Plugin.plugin,
			path: libpath
		};

		server.register(plugin, {}).then(() => {
			done();
		});
	});

	describe('Initialize with no options', () => {

		describe('ACL permissions', () => {

			it('returns an error when a user with unsuited permission tries to access a permission protected route', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hacli': {permission: 'ADMIN'}},
					handler: (request, h) => { return "TEST";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'USER'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			it('Allows access to protected method for multiple authorized permissions', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hacli': {permissions: ['USER', 'ADMIN']}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.payload).to.equal('Authorized');
						}, done);
					});
				});
			});

			it('returns an error when specifying permission (singular) with an array', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hacli': {permission: ['USER', 'ADMIN']}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(400);
							expect(res.result.message).to.equal('Invalid route options (Invalid settings) ValidationError: "permission" must be a string');
						}, done);
					});
				});
			});

			it('returns an error when specifying permissions (plural) with a string', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hacli': {permissions: 'USER'}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(400);
							expect(res.result.message).to.equal('Invalid route options (Invalid settings) ValidationError: "permissions" must be an array');
						}, done);
					});
				});
			});

			it('returns an error when specifying both permission and permissions as options', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hacli': {permission: 'USER', permissions: ['USER', 'ADMIN']}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(400);
							expect(res.result.message).to.equal('Invalid route options (Invalid settings) ValidationError: "permission" conflict with forbidden peer "permissions"');
						}, done);
					});
				});
			});

		});

		describe('fetchEntity', () => {

			it('validates that the aclQuery parameter is a function', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hacli': {aclQuery: 'not function'}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(400)
							expect(res.result.message).to.match(/"aclQuery" must be a Function/);
						}, done);
					});
				});
			});

			it('fetches the wanted entity using the query', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hacli': {aclQuery: (id, request) => {
						return {id: '1', name: 'Asaf'};
					}}},
					handler: (request, h) => { return request.plugins.hacli.entity;}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(200);
							expect(res.result.name).to.equal('Asaf');
						}, done);
					});
				});
			});

			it('handles not found entities', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hacli': {aclQuery: (id, request) => {
						return null;
					}}},
					handler: (request, h) => { return "Oops";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(404);
						}, done);
					});
				});
			});

			it('handles query errors', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hacli': {aclQuery: (id, request) => {
						throw new Error("Boomy");
					}}},
					handler: (request, h) => { return "Oops";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(400);
						}, done);
					});
				});
			});
		});

		describe('validateEntityAcl', () => {

			it('requires aclQuery when validateEntityAcl is true', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hacli': {validateEntityAcl: true}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(400);
							expect(res.result.message).to.match(/"aclQuery" is required/);
						}, done);
					});
				});
			});

			it('returns an error when the entity was not found', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hacli': {
						validateEntityAcl: true,
						aclQuery: (id, request) => {
							return null;
						}
					}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(404);
						}, done);
					});
				});
			});

			it('declines requests from unauthorized users', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hacli': {
						validateEntityAcl: true,
						validateAclMethod: 'isGranted',
						aclQuery: (id, request) => {
							return {id: id, name: 'Hello', isGranted: (user, permission) => { return false; }};
						}
					}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(403);
						}, done);
					});
				});
			});

			it('handles validator errors', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hacli': {
						validateEntityAcl: true,
						validateAclMethod: 'isGranted',
						aclQuery: (id, request) => {
							return {id: id, name: 'Hello', isGranted: (user, permission) => { throw new Error('Boom')}};
						}
					}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(500);
						}, done);
					});
				});
			});

			it('returns the response for authorized users', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hacli': {
						validateEntityAcl: true,
						validateAclMethod: 'isGranted',
						aclQuery: (id, request) => {
							return {id: id, name: 'Hello', isGranted: (user, permission) => { return true; }};
						}
					}},
					handler: (request, h) => {
						return request.plugins.hacli.entity;
					}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(200);
							expect(res.result.name).to.equal('Hello');
						}, done);
					});
				});
			});
		});

		describe('default acl validator', () => {

			it('returns error when the entity has no user field', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hacli': {
						validateEntityAcl: true,
						aclQuery: async (id, request) => {
							return {id: id, name: 'Hello'}
						}
					}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			it('returns error when the entity doesn\'t belong to the authenticated user', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hacli': {
						validateEntityAcl: true,
						aclQuery: (id, request) => {
              return {_user: '1', name: 'Hello'};
						}
					}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'ADMIN', _id: '2'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			it('returns the response for user with permissions', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hacli': {
						validateEntityAcl: true,
						aclQuery: (id, request) => {
              return {_user: '1', name: 'Hello'};
						}
					}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'ADMIN', _id: '1'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(200);
							expect(res.result).to.equal("Authorized");
						}, done);
					});
				});
			});

			it('handles custom user id field', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hacli': {
						validateEntityAcl: true,
						userIdField: 'myId',
						aclQuery: (id, request) => {
              return {_user: '1', name: 'Hello'};
						}
					}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'ADMIN', myId: '1'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(200);
							expect(res.result).to.equal("Authorized");
						}, done);
					});
				});
			});

			it('handles custom entity user field', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hacli': {
						validateEntityAcl: true,
						entityUserField: 'creator',
						aclQuery: (id, request) => {
              return {creator: '1', name: 'Hello'};
						}
					}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'ADMIN', _id: '1'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(200);
							expect(res.result).to.equal("Authorized");
						}, done);
					});
				});
			});

		});

		describe('Joi validator with aclQuery', () => {

			it('returns an error when query parameter is missing', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					validate: {
						query: {
							name: Joi.string().required()
						}
					},
					auth: 'default',
					plugins: {'hacli': {
						validateEntityAcl: true,
						entityUserField: 'creator',
						aclQueryParam: 'name',
						paramSource: 'query',
						aclQuery: (name, request) => {
							return {creator: '1', name: 'Hello' + name};
						}
					}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'ADMIN', _id: '1'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(400);
							expect(res.result.message).to.equal('Invalid request query input');
						}, done);
					});
				});
			});

			it('validates query parameter', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					validate: {
						query: {
							name: Joi.string().required()
						}
					},
					auth: 'default',
					plugins: {'hacli': {
						validateEntityAcl: true,
						entityUserField: 'creator',
						aclQueryParam: 'name',
						paramSource: 'query',
						aclQuery: (name, request) => {
							return {creator: '1', name: 'Hello' + name};
						}
					}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/?name=John Doe', credentials: {permission: 'ADMIN', _id: '1'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(200);
							expect(res.result).to.equal("Authorized");
						}, done);
					});
				});
			});

			it('returns an error when payload parameter is missing', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'POST', path: '/', options: {
					validate: {
						payload: {
							name: Joi.string().required()
						}
					},
					auth: 'default',
					plugins: {'hacli': {
						validateEntityAcl: true,
						entityUserField: 'creator',
						aclQueryParam: 'name',
						paramSource: 'payload',
						aclQuery: (name, request) => {
							return {creator: '1', name: 'Hello' + name};
						}
					}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'POST', url: '/', payload: {}, credentials: {permission: 'ADMIN', _id: '1'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(400);
							expect(res.result.message).to.equal('Invalid request payload input');
						}, done);
					});
				});
			});

			it('validates payload parameter', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'POST', path: '/', options: {
					validate: {
						payload: {
							name: Joi.string().required()
						}
					},
					auth: 'default',
					plugins: {'hacli': {
						validateEntityAcl: true,
						entityUserField: 'creator',
						aclQueryParam: 'name',
						paramSource: 'payload',
						aclQuery: (name, request) => {
							return {creator: '1', name: 'Hello' + name};
						}
					}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'POST', url: '/', payload: { name: "John Doe"}, credentials: {permission: 'ADMIN', _id: '1'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(200);
							expect(res.result).to.equal("Authorized");
						}, done);
					});
				});
			});

		});

	});

	describe('Initialize with permissions', () => {

		const plugin = {
			name: 'hacli',
			version: '0.0.0',
			register: Plugin.plugin.register,
			path: libpath,
			options: {
				permissions: ['OWNER', 'MANAGER', 'EMPLOYEE']
			}
		};

		describe('ACL permissions', () => {

			it('returns an error when a user with unsuited permission tries to access a permission protected route', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hacli': {permission: 'ADMIN'}},
					handler: (request, h) => { return "TEST";}
				}});
				server.register(plugin).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'USER'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			it('returns an error when a user with an invalid permission tries to access a permission protected route', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hacli': {permission: 'ADMIN'}},
					handler: (request, h) => { return "TEST";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'KING'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			it('Allows access to protected method for multiple authorized permissions', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hacli': {permissions: ['USER', 'ADMIN']}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.payload).to.equal('Authorized');
						}, done);
					});
				});
			});

			it('returns an error when specifying permission (singular) with an array', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hacli': {permission: ['USER', 'ADMIN']}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(400);
							expect(res.result.message).to.equal('Invalid route options (Invalid settings) ValidationError: "permission" must be a string');
						}, done);
					});
				});
			});

			it('returns an error when specifying permissions (plural) with a string', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hacli': {permissions: 'USER'}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(400);
							expect(res.result.message).to.equal('Invalid route options (Invalid settings) ValidationError: "permissions" must be an array');
						}, done);
					});
				});
			});

			it('returns an error when specifying both permission and permissions as options', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hacli': {permission: 'USER', permissions: ['USER', 'ADMIN']}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(400);
							expect(res.result.message).to.equal('Invalid route options (Invalid settings) ValidationError: "permission" conflict with forbidden peer "permissions"');
						}, done);
					});
				});
			});

			it('returns an error when a user with unsuited permission tries to access a permission protected route', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hacli': {permission: 'OWNER'}},
					handler: (request, h) => { return "TEST";}
				}});
				server.register(plugin).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'EMPLOYEE'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			it('returns an error when a user with a permission that is not a valid permission tries to access a permission protected route', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hacli': {permission: 'OWNER'}},
					handler: (request, h) => { return "TEST";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'KING'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			it('Allows access to protected method for a single permission', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hacli': {permission: 'EMPLOYEE'}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'EMPLOYEE'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(200);
							expect(res.payload).to.equal('Authorized');
						}, done);
					});
				});
			});

			it('Allows access to protected method for multiple authorized permissions', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hacli': {permissions: ['EMPLOYEE', 'MANAGER']}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'MANAGER'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.payload).to.equal('Authorized');
						}, done);
					});
				});
			});

			it('returns an error when a single permission is not one of the allowed permissions', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hacli': {permissions: ['OWNER', 'MANAGER']}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'EMPLOYEE'}}).then((res) => {
						internals.asyncCheck(() => {

							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			it('returns an error when specifying permission (singular) with an array', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hacli': {permission: ['USER', 'ADMIN']}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(400);
							expect(res.result.message).to.equal('Invalid route options (Invalid settings) ValidationError: "permission" must be a string');
						}, done);
					});
				});
			});

			it('returns an error when specifying permissions (plural) with a string', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hacli': {permissions: 'USER'}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(400);
							expect(res.result.message).to.equal('Invalid route options (Invalid settings) ValidationError: "permissions" must be an array');
						}, done);
					});
				});
			});

			it('returns an error when specifying both permission and permissions as options', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hacli': {permission: 'USER', permissions: ['USER', 'ADMIN']}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(400);
							expect(res.result.message).to.equal('Invalid route options (Invalid settings) ValidationError: "permission" conflict with forbidden peer "permissions"');
						}, done);
					});
				});
			});

		});

		describe('fetchEntity', () => {

			it('validates that the aclQuery parameter is a function', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hacli': {aclQuery: 'not function'}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(400)
							expect(res.result.message).to.match(/"aclQuery" must be a Function/);
						}, done);
					});
				});
			});

			it('fetches the wanted entity using the query', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hacli': {aclQuery: (id, request) => {
						return {id: '1', name: 'Asaf'};
					}}},
					handler: (request, h) => { return request.plugins.hacli.entity;}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(200);
							expect(res.result.name).to.equal('Asaf');
						}, done);
					});
				});
			});

			it('handles not found entities', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hacli': {aclQuery: (id, request) => {
						return null;
					}}},
					handler: (request, h) => { return "Oops";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(404);
						}, done);
					});
				});
			});

			it('handles query errors', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hacli': {aclQuery: (id, request) => {
						throw new Error("Boomy");
					}}},
					handler: (request, h) => { return "Oops";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(400);
						}, done);
					});
				});
			});
		});

		describe('validateEntityAcl', () => {

			it('requires aclQuery when validateEntityAcl is true', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hacli': {validateEntityAcl: true}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(400);
							expect(res.result.message).to.match(/"aclQuery" is required/);
						}, done);
					});
				});
			});

			it('returns an error when the entity was not found', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hacli': {
						validateEntityAcl: true,
						aclQuery: (id, request) => {
							return null;
						}
					}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(404);
						}, done);
					});
				});
			});

			it('declines requests from unauthorized users', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hacli': {
						validateEntityAcl: true,
						validateAclMethod: 'isGranted',
						aclQuery: (id, request) => {
              return {id: id, name: 'Hello', isGranted: (user, permission) => { return false; }};
						}
					}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(403);
						}, done);
					});
				});
			});

			it('handles validator errors', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hacli': {
						validateEntityAcl: true,
						validateAclMethod: 'isGranted',
						aclQuery: (id, request) => {
              return {id: id, name: 'Hello', isGranted: (user, permission) => { throw new Error('Boom'); }};
						}
					}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(500);
						}, done);
					});
				});
			});

			it('returns the response for authorized users', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hacli': {
						validateEntityAcl: true,
						validateAclMethod: 'isGranted',
						aclQuery: (id, request) => {
              return {id: id, name: 'Hello', isGranted: (user, permission) => { return true; }};
						}
					}},
					handler: (request, h) => {
						return request.plugins.hacli.entity;
					}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(200);
							expect(res.result.name).to.equal('Hello');
						}, done);
					});
				});
			});
		});

		describe('default acl validator', () => {

			it('returns error when the entity has no user field', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hacli': {
						validateEntityAcl: true,
						aclQuery: (id, request) => {
							return {id: id, name: 'Hello'};
						}
					}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			it('returns error when the entity doesn\'t belong to the authenticated user', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hacli': {
						validateEntityAcl: true,
						aclQuery: (id, request) => {
							return {_user: '1', name: 'Hello'};
						}
					}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'ADMIN', _id: '2'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			it('returns the response for user with permissions', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hacli': {
						validateEntityAcl: true,
						aclQuery: (id, request) => {
							return {_user: '1', name: 'Hello'};
						}
					}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'ADMIN', _id: '1'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(200);
							expect(res.result).to.equal("Authorized");
						}, done);
					});
				});
			});

			it('handles custom user id field', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hacli': {
						validateEntityAcl: true,
						userIdField: 'myId',
						aclQuery: (id, request) => {
							return {_user: '1', name: 'Hello'};
						}
					}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'ADMIN', myId: '1'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(200);
							expect(res.result).to.equal("Authorized");
						}, done);
					});
				});
			});

			it('handles custom entity user field', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hacli': {
						validateEntityAcl: true,
						entityUserField: 'creator',
						aclQuery: (id, request) => {
							return {creator: '1', name: 'Hello'};
						}
					}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'ADMIN', _id: '1'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(200);
							expect(res.result).to.equal("Authorized");
						}, done);
					});
				});
			});

		});

	});

	describe('Initialize with permissions list', () => {

		const plugin = {
			name: 'hacli',
			version: '0.0.0',
			plugin: Plugin.plugin,
			path: libpath,
			options: {
				permissions: ['OWNER', 'MANAGER', 'EMPLOYEE']
			}
		};

		describe('ACL permissions', () => {

			it('should allow access when accessing a permission protected route', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
						auth: 'default',
						plugins: {'hacli': {permission: 'OWNER'}},
						handler: (request, h) => { return "TEST";}
					}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'OWNER'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(200);
						}, done);
					});
				});
			});

			it('should allow access when accessing a permission protected route with a user with multiple permissions', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
						auth: 'default',
						plugins: {'hacli': {permission: 'OWNER'}},
						handler: (request, h) => { return "TEST";}
					}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: ['OWNER', 'EMPLOYEE']}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(200);
						}, done);
					});
				});
			});

			it('returns an error when a user with unsuited permissions list tries to access a permission protected route', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
						auth: 'default',
						plugins: {'hacli': {permission: 'OWNER'}},
						handler: (request, h) => { return "TEST";}
					}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: ['MANAGER', 'EMPLOYEE']}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			it('returns an error when a user with unsuited permission tries to access a permission protected route', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hacli': {permission: 'ADMIN'}},
					handler: (request, h) => { return "TEST";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'USER'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			it('returns an error when a user with an invalid permission tries to access a permission protected route', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hacli': {permission: 'ADMIN'}},
					handler: (request, h) => { return "TEST";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'KING'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			it('returns an error when specifying permission (singular) with an array', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hacli': {permission: ['USER', 'ADMIN']}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(400);
							expect(res.result.message).to.equal('Invalid route options (Invalid settings) ValidationError: "permission" must be a string');
						}, done);
					});
				});
			});

			it('returns an error when specifying permissions (plural) with a string', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hacli': {permissions: 'USER'}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(400);
							expect(res.result.message).to.equal('Invalid route options (Invalid settings) ValidationError: "permissions" must be an array');
						}, done);
					});
				});
			});

			it('returns an error when specifying both permission and permissions as options', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hacli': {permission: 'USER', permissions: ['USER', 'ADMIN']}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(400);
							expect(res.result.message).to.equal('Invalid route options (Invalid settings) ValidationError: "permission" conflict with forbidden peer "permissions"');
						}, done);
					});
				});
			});

			it('returns an error when a user with unsuited permission tries to access a permission protected route', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hacli': {permission: 'OWNER'}},
					handler: (request, h) => { return "TEST";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'EMPLOYEE'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			it('returns an error when a user with a permission that is not a valid permission tries to access a permission protected route', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hacli': {permission: 'OWNER'}},
					handler: (request, h) => { return "TEST";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'KING'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			it('Allows access to protected method for a single permission', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hacli': {permission: 'EMPLOYEE'}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'EMPLOYEE'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(200);
							expect(res.payload).to.equal('Authorized');
						}, done);
					});
				});
			});

			it('Allows access to protected method for multiple authorized permissions', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hacli': {permissions: ['EMPLOYEE', 'MANAGER']}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'MANAGER'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.payload).to.equal('Authorized');
						}, done);
					});
				});
			});

			it('returns an error when a single permission is not one of the allowed permissions', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hacli': {permissions: ['OWNER', 'MANAGER']}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'EMPLOYEE'}}).then((res) => {
						internals.asyncCheck(() => {

							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			it('returns an error when specifying permission (singular) with an array', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hacli': {permission: ['USER', 'ADMIN']}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(400);
							expect(res.result.message).to.equal('Invalid route options (Invalid settings) ValidationError: "permission" must be a string');
						}, done);
					});
				});
			});

			it('returns an error when specifying permissions (plural) with a string', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hacli': {permissions: 'USER'}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(400);
							expect(res.result.message).to.equal('Invalid route options (Invalid settings) ValidationError: "permissions" must be an array');
						}, done);
					});
				});
			});

			it('returns an error when specifying both permission and permissions as options', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hacli': {permission: 'USER', permissions: ['USER', 'ADMIN']}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(400);
							expect(res.result.message).to.equal('Invalid route options (Invalid settings) ValidationError: "permission" conflict with forbidden peer "permissions"');
						}, done);
					});
				});
			});

		});

		describe('fetchEntity', () => {

			it('validates that the aclQuery parameter is a function', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hacli': {aclQuery: 'not function'}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(400)
							expect(res.result.message).to.match(/"aclQuery" must be a Function/);
						}, done);
					});
				});
			});

			it('fetches the wanted entity using the query', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hacli': {aclQuery: (id, request) => {
						return {id: '1', name: 'Asaf'};
					}}},
					handler: (request, h) => { return request.plugins.hacli.entity;}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(200);
							expect(res.result.name).to.equal('Asaf');
						}, done);
					});
				});
			});

			it('handles not found entities', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hacli': {aclQuery: (id, request) => {
						return null;
					}}},
					handler: (request, h) => { return "Oops";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(404);
						}, done);
					});
				});
			});

			it('handles query errors', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hacli': {aclQuery: (id, request) => {
						throw new Error("Boomy");
					}}},
					handler: (request, h) => { return "Oops";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(400);
						}, done);
					});
				});
			});

		});

		describe('validateEntityAcl', () => {

			it('requires aclQuery when validateEntityAcl is true', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hacli': {validateEntityAcl: true}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(400);
							expect(res.result.message).to.match(/"aclQuery" is required/);
						}, done);
					});
				});
			});

			it('returns an error when the entity was not found', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hacli': {
						validateEntityAcl: true,
						aclQuery: (id, request) => {
							return null;
						}
					}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(404);
						}, done);
					});
				});
			});

			it('declines requests from unauthorized users', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hacli': {
						validateEntityAcl: true,
						validateAclMethod: 'isGranted',
						aclQuery: (id, request) => {
							return {id: id, name: 'Hello', isGranted: (user, permission) => { return false; }};
						}
					}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(403);
						}, done);
					});
				});
			});

			it('handles validator errors', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hacli': {
						validateEntityAcl: true,
						validateAclMethod: 'isGranted',
						aclQuery: (id, request) => {
							return {id: id, name: 'Hello', isGranted: (user, permission) => { throw new Error('Boom')}};
						}
					}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(500);
						}, done);
					});
				});
			});

			it('returns the response for authorized users', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hacli': {
						validateEntityAcl: true,
						validateAclMethod: 'isGranted',
						aclQuery: (id, request) => {
							return {id: id, name: 'Hello', isGranted: (user, permission) => { return true; }};
						}
					}},
					handler: (request, h) => {
						return request.plugins.hacli.entity;
					}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(200);
							expect(res.result.name).to.equal('Hello');
						}, done);
					});
				});
			});

		});

		describe('default acl validator', () => {

			it('returns error when the entity has no user field', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hacli': {
						validateEntityAcl: true,
						aclQuery: (id, request) => {
							return {id: id, name: 'Hello'};
						}
					}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			it('returns error when the entity doesn\'t belong to the authenticated user', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hacli': {
						validateEntityAcl: true,
						aclQuery: (id, request) => {
							return {_user: '1', name: 'Hello'};
						}
					}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'ADMIN', _id: '2'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			it('returns the response for user with permissions', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hacli': {
						validateEntityAcl: true,
						aclQuery: (id, request) => {
							return {_user: '1', name: 'Hello'};
						}
					}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'ADMIN', _id: '1'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(200);
							expect(res.result).to.equal("Authorized");
						}, done);
					});
				});
			});

			it('handles custom user id field', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hacli': {
						validateEntityAcl: true,
						userIdField: 'myId',
						aclQuery: (id, request) => {
							return {_user: '1', name: 'Hello'};
						}
					}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'ADMIN', myId: '1'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(200);
							expect(res.result).to.equal("Authorized");
						}, done);
					});
				});
			});

			it('handles custom entity user field', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hacli': {
						validateEntityAcl: true,
						entityUserField: 'creator',
						aclQuery: (id, request) => {
							return {creator: '1', name: 'Hello'};
						}
					}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'ADMIN', _id: '1'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(200);
							expect(res.result).to.equal("Authorized");
						}, done);
					});
				});
			});

		});

	});

	describe('Initialize with permissions hierarchy', () => {

		const plugin = {
			name: 'hacli',
			version: '0.0.0',
			plugin: Plugin.plugin,
			path: libpath,
			options: {
				permissions: {
					OWNER: {
						MANAGER: {
							SECRETARY: {}
						},
						EMPLOYEE: {
							USER: {
								INTERN: {}
							}
						}
					}
				}
			}
		};

		describe('ACL permissions', () => {

			it('should allow access when accessing a permission protected route', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
						auth: 'default',
						plugins: {'hacli': {permission: 'OWNER'}},
						handler: (request, h) => { return "TEST";}
					}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'OWNER'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(200);
						}, done);
					});
				});
			});

			it('should allow access when accessing a permission protected route with user with an higher permission', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
						auth: 'default',
						plugins: {'hacli': {permission: 'USER'}},
						handler: (request, h) => { return "TEST";}
					}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'OWNER'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(200);
						}, done);
					});
				});
			});

			it('should allow access when accessing a permission protected route with a user with multiple permissions with an higher permission', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
						auth: 'default',
						plugins: {'hacli': {permission: 'SECRETARY'}},
						handler: (request, h) => { return "TEST";}
					}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: ['MANAGER', 'USER']}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(200);
						}, done);
					});
				});
			});

			it('returns an error when a user with unsuited permissions list tries to access a permission protected route', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
						auth: 'default',
						plugins: {'hacli': {permission: 'OWNER'}},
						handler: (request, h) => { return "TEST";}
					}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: ['MANAGER', 'EMPLOYEE']}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			it('returns an error when a user with unsuited permission tries to access a permission protected route', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hacli': {permission: 'OWNER'}},
					handler: (request, h) => { return "TEST";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'INTERN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			it('returns an error when a user with an invalid permission tries to access a permission protected route', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hacli': {permission: 'ADMIN'}},
					handler: (request, h) => { return "TEST";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'KING'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			it('Allows access to protected method for multiple authorized permissions', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hacli': {permissions: ['USER', 'ADMIN']}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.payload).to.equal('Authorized');
						}, done);
					});
				});
			});

			it('returns an error when specifying permission (singular) with an array', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hacli': {permission: ['USER', 'ADMIN']}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(400);
							expect(res.result.message).to.equal('Invalid route options (Invalid settings) ValidationError: "permission" must be a string');
						}, done);
					});
				});
			});

			it('returns an error when specifying permissions (plural) with a string', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hacli': {permissions: 'USER'}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(400);
							expect(res.result.message).to.equal('Invalid route options (Invalid settings) ValidationError: "permissions" must be an array');
						}, done);
					});
				});
			});

			it('returns an error when specifying both permission and permissions as options', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hacli': {permission: 'USER', permissions: ['USER', 'ADMIN']}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(400);
							expect(res.result.message).to.equal('Invalid route options (Invalid settings) ValidationError: "permission" conflict with forbidden peer "permissions"');
						}, done);
					});
				});
			});

			it('returns an error when a user with unsuited permission tries to access a permission protected route', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hacli': {permission: 'OWNER'}},
					handler: (request, h) => { return "TEST";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'EMPLOYEE'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			it('returns an error when a user with a permission that is not a valid permission tries to access a permission protected route', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hacli': {permission: 'OWNER'}},
					handler: (request, h) => { return "TEST";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'KING'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			it('Allows access to protected method for a single permission', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hacli': {permission: 'EMPLOYEE'}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'EMPLOYEE'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(200);
							expect(res.payload).to.equal('Authorized');
						}, done);
					});
				});
			});

			it('Allows access to protected method for multiple authorized permissions', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hacli': {permissions: ['EMPLOYEE', 'MANAGER']}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'MANAGER'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.payload).to.equal('Authorized');
						}, done);
					});
				});
			});

			it('returns an error when a single permission is not one of the allowed permissions', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hacli': {permissions: ['OWNER', 'MANAGER']}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'EMPLOYEE'}}).then((res) => {
						internals.asyncCheck(() => {

							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			it('returns an error when specifying permission (singular) with an array', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hacli': {permission: ['USER', 'ADMIN']}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(400);
							expect(res.result.message).to.equal('Invalid route options (Invalid settings) ValidationError: "permission" must be a string');
						}, done);
					});
				});
			});

			it('returns an error when specifying permissions (plural) with a string', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hacli': {permissions: 'USER'}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(400);
							expect(res.result.message).to.equal('Invalid route options (Invalid settings) ValidationError: "permissions" must be an array');
						}, done);
					});
				});
			});

			it('returns an error when specifying both permission and permissions as options', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hacli': {permission: 'USER', permissions: ['USER', 'ADMIN']}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(400);
							expect(res.result.message).to.equal('Invalid route options (Invalid settings) ValidationError: "permission" conflict with forbidden peer "permissions"');
						}, done);
					});
				});
			});
		});

/*
		describe('fetchEntity', () => {

			it('validates that the aclQuery parameter is a function', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hacli': {aclQuery: 'not function'}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(400)
							expect(res.result.message).to.match(/"aclQuery" must be a Function/);
						}, done);
					});
				});
			});

			it('fetches the wanted entity using the query', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hacli': {aclQuery: (id, request) => {
						return {id: '1', name: 'Asaf'};
					}}},
					handler: (request, h) => { return request.plugins.hacli.entity;}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(200);
							expect(res.result.name).to.equal('Asaf');
						}, done);
					});
				});
			});

			it('handles not found entities', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hacli': {aclQuery: (id, request) => {
						return null;
					}}},
					handler: (request, h) => { return "Oops";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(404);
						}, done);
					});
				});
			});

			it('handles query errors', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hacli': {aclQuery: (id, request) => {
						throw new Error("Boomy");
					}}},
					handler: (request, h) => { return "Oops";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(400);
						}, done);
					});
				});
			});
		});

		describe('validateEntityAcl', () => {

			it('requires aclQuery when validateEntityAcl is true', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hacli': {validateEntityAcl: true}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(400);
							expect(res.result.message).to.match(/"aclQuery" is required/);
						}, done);
					});
				});
			});

			it('returns an error when the entity was not found', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hacli': {
						validateEntityAcl: true,
						aclQuery: (id, request) => {
							return null;
						}
					}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(404);
						}, done);
					});
				});
			});

			it('declines requests from unauthorized users', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hacli': {
						validateEntityAcl: true,
						validateAclMethod: 'isGranted',
						aclQuery: (id, request) => {
							return {id: id, name: 'Hello', isGranted: (user, permission) => { return false; }};
						}
					}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(403);
						}, done);
					});
				});
			});

			it('handles validator errors', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hacli': {
						validateEntityAcl: true,
						validateAclMethod: 'isGranted',
						aclQuery: (id, request) => {
							return {id: id, name: 'Hello', isGranted: (user, permission) => { throw new Error('Boom')}};
						}
					}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(500);
						}, done);
					});
				});
			});

			it('returns the response for authorized users', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hacli': {
						validateEntityAcl: true,
						validateAclMethod: 'isGranted',
						aclQuery: (id, request) => {
							return {id: id, name: 'Hello', isGranted: (user, permission) => { return true; }};
						}
					}},
					handler: (request, h) => {
						return request.plugins.hacli.entity;
					}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(200);
							expect(res.result.name).to.equal('Hello');
						}, done);
					});
				});
			});

		});

		describe('default acl validator', () => {

			it('returns error when the entity has no user field', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hacli': {
						validateEntityAcl: true,
						aclQuery: (id, request) => {
							return {id: id, name: 'Hello'};
						}
					}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			it('returns error when the entity doesn\'t belong to the authenticated user', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hacli': {
						validateEntityAcl: true,
						aclQuery: (id, request) => {
							return {_user: '1', name: 'Hello'};
						}
					}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'ADMIN', _id: '2'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			it('returns the response for user with permissions', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hacli': {
						validateEntityAcl: true,
						aclQuery: (id, request) => {
							return {_user: '1', name: 'Hello'};
						}
					}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'ADMIN', _id: '1'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(200);
							expect(res.result).to.equal("Authorized");
						}, done);
					});
				});
			});

			it('handles custom user id field', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hacli': {
						validateEntityAcl: true,
						userIdField: 'myId',
						aclQuery: (id, request) => {
							return {_user: '1', name: 'Hello'};
						}
					}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'ADMIN', myId: '1'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(200);
							expect(res.result).to.equal("Authorized");
						}, done);
					});
				});
			});

			it('handles custom entity user field', (done) => {
				const server = new Hapi.Server();

				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hacli': {
						validateEntityAcl: true,
						entityUserField: 'creator',
						aclQuery: (id, request) => {
							return {creator: '1', name: 'Hello'};
						}
					}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {permission: 'ADMIN', _id: '1'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(200);
							expect(res.result).to.equal("Authorized");
						}, done);
					});
				});
			});

		});
*/
	});
});

internals.authSchema = () => {

	const scheme = {
		authenticate: (request, h) => {
			return { username: "asafdav", permission: 'INTERN'};
		},
		payload: (request, h) => {
			return request.auth.credentials.payload;
		},
		response: (request, h) => {
			return {};
		}
	};

	return scheme;
};

internals.asyncCheck = (f, done) => {
	try {
		f();
		done();
	} catch(e) {
		done(e);
	}
}

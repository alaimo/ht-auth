module.exports = function(grunt) {
	// load plugins
	[
		'grunt-mocha-test',
		'grunt-contrib-jshint'
	].forEach(function(task) {
		grunt.loadNpmTasks(task);
	});

	// configure plugins
	grunt.initConfig({
		jshint: {
			module: [
				'HtAuth.js'
			],
			test: [
				'Gruntfile.js',
				'test/**/*.js'
			]
		},
		mochaTest: {
			test: {
				options: {
					mocha: require('mocha')
				},
				src: ['test/test-*.js']
			}
		}
	});

	// register tasks
	grunt.registerTask('default', ['jshint', 'mochaTest']);
};
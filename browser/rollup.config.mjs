
import terser from '@rollup/plugin-terser';
import resolve from '@rollup/plugin-node-resolve';
import commonjs from '@rollup/plugin-commonjs';

export default 
[
{
	input: './src/senclave.js',
	output: [
		{
			sourcemap:true,
			format: 'iife',
			name: 'SEnclave',
			file: './dist/senclave.min.js',
 			plugins: [terser()]
		}
	],
	plugins: [
		resolve(),
		commonjs()
	]
}
]

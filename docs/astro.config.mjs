// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

// https://astro.build/config
export default defineConfig({
	integrations: [
		starlight({
			title: 'SecretSpec',
			tagline: 'Declarative secrets for development workflows',
			social: [
				{ icon: 'github', label: 'GitHub', href: 'https://github.com/cachix/secretspec' },
				{ icon: 'discord', label: 'Discord', href: 'https://discord.gg/naMgvexb6q' },
			],
			sidebar: [
				{
					label: 'Getting Started',
					items: [
						{ label: 'Quick Start', slug: 'quick-start' },
					],
				},
				{
					label: 'Concepts',
					items: [
						{ label: 'Declarative Configuration', slug: 'concepts/declarative' },
						{ label: 'Profiles', slug: 'concepts/profiles' },
						{ label: 'Providers', slug: 'concepts/providers' },
					],
				},
				{
					label: 'Providers',
					items: [
						{ label: 'Keyring', slug: 'providers/keyring' },
						{ label: 'Dotenv', slug: 'providers/dotenv' },
						{ label: 'Environment Variables', slug: 'providers/env' },
						{ label: 'LastPass', slug: 'providers/lastpass' },
						{ label: '1Password', slug: 'providers/1password' },
					],
				},
				{
					label: 'SDK',
					items: [
						{ label: 'Rust SDK', slug: 'sdk/rust' },
					],
				},
				{
					label: 'Reference',
					items: [
						{ label: 'Configuration', slug: 'reference/configuration' },
						{ label: 'CLI Commands', slug: 'reference/cli' },
						{ label: 'Adding Providers', slug: 'reference/adding-providers' },
					],
				},
			],
		}),
	],
});

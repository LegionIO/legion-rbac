# frozen_string_literal: true

require_relative 'lib/legion/rbac/version'

Gem::Specification.new do |spec|
  spec.name = 'legion-rbac'
  spec.version       = Legion::Rbac::VERSION
  spec.authors       = ['Esity']
  spec.email         = ['matthewdiverson@gmail.com']

  spec.summary       = 'Legion::Rbac'
  spec.description   = 'Role-based access control for LegionIO with team scoping and policy enforcement'
  spec.homepage      = 'https://github.com/LegionIO/legion-rbac'
  spec.license       = 'Apache-2.0'
  spec.require_paths = ['lib']
  spec.required_ruby_version = '>= 3.4'
  spec.files = `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  spec.extra_rdoc_files = %w[README.md LICENSE CHANGELOG.md]
  spec.metadata = {
    'bug_tracker_uri'       => 'https://github.com/LegionIO/legion-rbac/issues',
    'changelog_uri'         => 'https://github.com/LegionIO/legion-rbac/blob/main/CHANGELOG.md',
    'documentation_uri'     => 'https://github.com/LegionIO/legion-rbac',
    'homepage_uri'          => 'https://github.com/LegionIO/legion-rbac',
    'source_code_uri'       => 'https://github.com/LegionIO/legion-rbac',
    'wiki_uri'              => 'https://github.com/LegionIO/legion-rbac/wiki',
    'rubygems_mfa_required' => 'true'
  }

  spec.add_dependency 'legion-json', '>= 1.2.0'
  spec.add_dependency 'legion-logging', '>= 1.4.3'
  spec.add_dependency 'legion-settings', '>= 1.3.12'
end

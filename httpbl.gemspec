Gem::Specification.new do |s|
  s.name = 'httpbl'
  s.version = '0.1.5'
  s.date = '2009-05-03'
  s.homepage = "http://bpalmen.github.com/httpbl/"   
  s.authors = ["Brandon Palmen"]
  s.email = "brandon.palmen@gmail.com"
  s.rubyforge_project = 'httpbl'   
  s.summary = "HttpBL is a Rack middleware filter that blocks requests from suspicious IP addresses."
  s.description = "HttpBL is a Rack middleware filter that blocks requests from suspicious IP addresses."
   
  s.files = %w[ 
    README
    CHANGELOG
    LICENSE
    lib/httpbl.rb
    ]
  
  s.add_dependency 'rack', '>= 0.9.0'
  s.extra_rdoc_files = %w[README]
  s.require_paths = %w[lib]
end 

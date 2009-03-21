Gem::Specification.new do |s|
  s.name = 'httpbl'
  s.version = '0.2.0'
  s.date = '2009-03-20'
   
  s.authors = ["Brandon Palmen"]
  s.email = "brandon.palmen@gmail.com"
   
  s.summary = "HttpBL is a Rack/Rails middleware filter that blocks requests from suspicious IP addresses."
  s.description = "HttpBL is a Rack/Rails middleware filter that blocks requests from suspicious IP addresses."
   
  s.files = %w[ 
    README
    Changelog
    LICENSE
    lib/httpbl.rb
    ]
  
  s.add_dependency 'rack', '~> 0.4'
  s.extra_rdoc_files = %w[README]
  s.require_paths = %w[lib]
end 
# The Httpbl middleware 

class HttpBL
  autoload :Resolv, 'resolv'
  
  def initialize(app, options = {})
    @app = app
    @options = {:blocked_search_engines => [],
                :age_threshold => 10,
                :threat_level_threshold => 2,
                :deny_types => [1, 2, 4, 8, 16, 32, 64, 128], # 8..128 aren't used as of 3/2009, but might be used in the future
                :dns_timeout => 0.5,
                :memcached_server => nil
                }.merge(options)
    raise "Missing :api_key for Http:BL middleware" unless @options[:api_key]
    if @options[:memcached_server]
      require 'memcache'
      @cache = MemCache.new(@options[:memcached_server], @options[:memcached_options])
    end
  end
  
  def call(env)
    dup._call(env)
  end
  
  def _call(env)
    request = Rack::Request.new(env)
    bl_status = check(request.ip)
    if bl_status and blocked?(bl_status)
      [403, {"Content-Type" => "text/html"}, "<h1>403 Forbidden</h1> Request IP is listed as suspicious by <a href='http://projecthoneypot.org/ip_#{request.ip}'>Project Honeypot</a>"]
    else
      @app.call(env)
    end
    
  end
  
  def check(ip)
    @cache ? cache_check(ip) : resolve(ip)
  end
  
  def cache_check(ip)
    cache = @cache.clone if @cache
    unless response = cache.get(ip)
      response = resolve(ip)
      cache.set(ip, (response || "0.0.0.0"), 1.hour)
    end
    return response
  end
  
  def resolve(ip)
    query = @options[:api_key] + '.' + ip.split('.').reverse.join('.') + '.dnsbl.httpbl.org'
    Timeout::timeout(@options[:dns_timeout]) do
       Resolv::DNS.new.getaddress(query).to_s rescue nil
    end
    rescue Timeout::Error, Errno::ECONNREFUSED
  end
  
  def blocked?(response)
    response = response.split('.').collect!(&:to_i)
    if response[0] == 127 
      if response[3] == 0
        @blocked = @options[:blocked_search_engines].include?(response[2])
      else 
        @blocked = @options[:deny_types].collect{|key| response[3] & key == key }.any?
        @blocked = @blocked and response[2] > @options[:threat_level_threshold] 
        @blocked = @blocked and response[1] < @options[:age_threshold]
      end
    end
    return @blocked
  end

end

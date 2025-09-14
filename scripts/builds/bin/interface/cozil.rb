# cozil.rb
# Initializes the Cozil module inside the JavaScript engine.

module Cozil
  # A class to represent a Cozil object
  class CozilObject
    def initialize(data)
      @data = data
    end

    def to_js
      @data.to_json
    end
  end

  # A method to create a new Cozil object
  def self.create(data)
    CozilObject.new(data)
  end

  # A method to evaluate a JavaScript expression
  def self.eval(js_code)
    `#{js_code}` # execute the JavaScript code using the backtick operator
  end

  # A method to execute a JavaScript function
  def self.exec(js_func, *args)
    eval "#{js_func}(#{args.map(&:to_js).join(', ')})"
  end
end
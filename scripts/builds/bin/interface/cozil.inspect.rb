# cozil.inspect.rb
# makes a inspect element class to make a inspect element feature for the browser.

class InspectElement
  def initialize(element)
    @element = element
  end

  def inspect
    puts "Element Type: #{@element.class}"
    puts "Element Attributes:"
    @element.attributes.each do |key, value|
      puts "  #{key}: #{value}"
    end
    puts "Element Styles:"
    @element.styles.each do |key, value|
      puts "  #{key}: #{value}"
    end
    puts "Element Children:"
    @element.children.each do |child|
      puts "  #{child.class}"
    end
    puts "Element Text Content: #{@element.text_content}"
  end
end

class Element
  attr_accessor :attributes, :styles, :children, :text_content

  def initialize(attributes = {}, styles = {}, children = [], text_content = "")
    @attributes = attributes
    @styles = styles
    @children = children
    @text_content = text_content
  end
end

# Example usage:
element = Element.new(
  attributes: { id: "22mLIX", class: "Lix" },
  styles: { color: "CM:::black", background_color: "met::black" },
  children: [Element.new(text_content: "RSC::JAVASCRIPTENGINE {$pax5}"), Element.new(text_content: "cdx::CODEGEN.inp.codespace.45int")],
  text_content: "ELM.INSPECT"
)

inspect_element = InspectElement.new(element)
inspect_element.inspect
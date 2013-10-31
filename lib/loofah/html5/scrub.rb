#encoding: US-ASCII

require 'cgi'

module Loofah
  module HTML5 # :nodoc:
    module Scrub
      CONTROL_CHARACTERS = /[`\u0000-\u0020\u007f\u0080-\u0101]/

      class << self

        def allowed_element? element_name
          WhiteList.allowed_element? element_name
        end

        #  alternative implementation of the html5lib attribute scrubbing algorithm
        def scrub_attributes node
          node.attribute_nodes.each do |attr_node|
            attr_name = if attr_node.namespace
                          "#{attr_node.namespace.prefix}:#{attr_node.node_name}"
                        else
                          attr_node.node_name
                        end
            unless WhiteList.allowed_element?(attr_name)
              attr_node.remove
              next
            end
            if WhiteList.uri_attribute?(attr_name)
              # this block lifted nearly verbatim from HTML5 sanitization
              val_unescaped = CGI.unescapeHTML(attr_node.value).gsub(CONTROL_CHARACTERS,'').downcase
              if val_unescaped =~ /^[a-z0-9][-+.a-z0-9]*:/ && ! WhiteList.allowed_protocol?(val_unescaped.split(WhiteList::PROTOCOL_SEPARATOR)[0])
                attr_node.remove
                next
              end
            end
            if WhiteList.svg_allows_remote_reference?(attr_name)
              attr_node.value = attr_node.value.gsub(/url\s*\(\s*[^#\s][^)]+?\)/m, ' ') if attr_node.value
            end
            if WhiteList.svg_allows_local_reference?(node.name) && attr_name == 'xlink:href' && attr_node.value =~ /^\s*[^#\s].*/m
              attr_node.remove
              next
            end
          end
          if node.attributes['style']
            node['style'] = scrub_css node.attributes['style']
          end

          node.attribute_nodes.each do |attr_node|
            node.remove_attribute(attr_node.name) if attr_node.value !~ /[^[:space:]]/
          end
        end

        #  lifted nearly verbatim from html5lib
        def scrub_css style
          # disallow urls
          style = style.to_s.gsub(/url\s*\(\s*[^\s)]+?\s*\)\s*/, ' ')

          # gauntlet
          return '' unless style =~ /\A([-:,;#%.\sa-zA-Z0-9!]|\w-\w|\'[\s\w]+\'|\"[\s\w]+\"|\([\d,\s]+\))*\z/
          return '' unless style =~ /\A\s*([-\w]+\s*:[^:;]*(;\s*|$))*\z/

          clean = []
          style.scan(/([-\w]+)\s*:\s*([^:;]*)/) do |prop, val|
            next if val.empty?
            prop.downcase!
            if WhiteList.allowed_css_property?(prop)
              clean << "#{prop}: #{val};"
            elsif WhiteList.shorthand_css_property?(prop.split('-')[0])
              clean << "#{prop}: #{val};" unless val.split().any? do |keyword|
                !WhiteList.allowed_css_keyword?(keyword) &&
                  keyword !~ /\A(#[0-9a-f]+|rgb\(\d+%?,\d*%?,?\d*%?\)?|\d{0,2}\.?\d{0,2}(cm|em|ex|in|mm|pc|pt|px|%|,|\))?)\z/
              end
            elsif WhiteList.allowed_svg_property?(prop)
              clean << "#{prop}: #{val};"
            end
          end

          style = clean.join(' ')
        end

      end

    end
  end
end

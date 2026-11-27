-- Strip presentation wrappers while retaining explicit HTML fragment targets.
local function anchor(identifier)
  return pandoc.RawBlock('html', '<a id="' .. identifier .. '"></a>')
end

function Div(element)
  local blocks = pandoc.List()
  if element.identifier ~= '' then
    blocks:insert(anchor(element.identifier))
  end
  blocks:extend(element.content)
  return blocks
end

function Header(element)
  if element.identifier == '' then return element end
  return { anchor(element.identifier), element }
end

function Span(element)
  local inlines = pandoc.List()
  if element.identifier ~= '' then
    inlines:insert(pandoc.RawInline('html', '<a id="' .. element.identifier .. '"></a>'))
  end
  inlines:extend(element.content)
  return inlines
end

function DefinitionList(element)
  local blocks = pandoc.List()
  for _, entry in ipairs(element.content) do
    blocks:insert(pandoc.Para({ pandoc.Strong(entry[1]) }))
    for _, definition in ipairs(entry[2]) do
      blocks:extend(definition)
    end
  end
  return blocks
end

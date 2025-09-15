import dom, jsffi, strutils, tables, times

type
  TooltipPosition* = enum
    tpTop, tpBottom, tpLeft, tpRight, tpAuto

  TooltipConfig* = object
    text*: cstring
    position*: TooltipPosition
    delay*: int  # milliseconds
    maxWidth*: int  # pixels
    className*: cstring
    html*: bool  # allow HTML content

  TooltipManager* = ref object
    tooltips: Table[cstring, Element]
    activeTooltip: Element
    showTimer: int
    hideTimer: int
    config: TooltipConfig

var tooltipManager*: TooltipManager

proc createTooltipElement(text: cstring, config: TooltipConfig): Element =
  let tooltip = document.createElement("div")
  tooltip.className = cstring("aluminum-tooltip " & $config.className)
  
  if config.html:
    tooltip.innerHTML = text
  else:
    tooltip.textContent = text
  
  tooltip.style.position = "absolute"
  tooltip.style.zIndex = "10000"
  tooltip.style.padding = "8px 12px"
  tooltip.style.backgroundColor = "#333"
  tooltip.style.color = "white"
  tooltip.style.borderRadius = "4px"
  tooltip.style.fontSize = "12px"
  tooltip.style.whiteSpace = "nowrap"
  tooltip.style.pointerEvents = "none"
  tooltip.style.opacity = "0"
  tooltip.style.transition = "opacity 0.2s ease-in-out"
  tooltip.style.boxShadow = "0 2px 8px rgba(0,0,0,0.15)"
  
  if config.maxWidth > 0:
    tooltip.style.maxWidth = cstring($config.maxWidth & "px")
    tooltip.style.whiteSpace = "normal"
    tooltip.style.wordWrap = "break-word"
  
  document.body.appendChild(tooltip)
  return tooltip

proc calculatePosition(element: Element, tooltip: Element, position: TooltipPosition): (int, int) =
  let rect = element.getBoundingClientRect()
  let tooltipRect = tooltip.getBoundingClientRect()
  let scrollX = window.pageXOffset
  let scrollY = window.pageYOffset
  
  var x, y: int
  
  case position:
  of tpTop:
    x = int(rect.left + scrollX + (rect.width / 2) - (tooltipRect.width / 2))
    y = int(rect.top + scrollY - tooltipRect.height - 8)
  of tpBottom:
    x = int(rect.left + scrollX + (rect.width / 2) - (tooltipRect.width / 2))
    y = int(rect.top + scrollY + rect.height + 8)
  of tpLeft:
    x = int(rect.left + scrollX - tooltipRect.width - 8)
    y = int(rect.top + scrollY + (rect.height / 2) - (tooltipRect.height / 2))
  of tpRight:
    x = int(rect.left + scrollX + rect.width + 8)
    y = int(rect.top + scrollY + (rect.height / 2) - (tooltipRect.height / 2))
  of tpAuto:
    # Choose best position based on available space
    let viewportWidth = window.innerWidth
    let viewportHeight = window.innerHeight
    
    if rect.top > tooltipRect.height + 8:
      return calculatePosition(element, tooltip, tpTop)
    elif rect.bottom + tooltipRect.height + 8 < viewportHeight:
      return calculatePosition(element, tooltip, tpBottom)
    elif rect.left > tooltipRect.width + 8:
      return calculatePosition(element, tooltip, tpLeft)
    else:
      return calculatePosition(element, tooltip, tpRight)
  
  # Keep tooltip within viewport bounds
  x = max(8, min(x, int(window.innerWidth) - int(tooltipRect.width) - 8))
  y = max(8, min(y, int(window.innerHeight) - int(tooltipRect.height) - 8))
  
  return (x, y)

proc showTooltip(element: Element, config: TooltipConfig) =
  if tooltipManager.activeTooltip != nil:
    hideTooltip()
  
  let tooltip = createTooltipElement(config.text, config)
  tooltipManager.activeTooltip = tooltip
  
  # Position tooltip (initially hidden to calculate dimensions)
  let (x, y) = calculatePosition(element, tooltip, config.position)
  tooltip.style.left = cstring($x & "px")
  tooltip.style.top = cstring($y & "px")
  
  # Show tooltip with fade-in effect
  discard setTimeout(proc() = tooltip.style.opacity = "1", 10)

proc hideTooltip*() =
  if tooltipManager.activeTooltip != nil:
    let tooltip = tooltipManager.activeTooltip
    tooltip.style.opacity = "0"
    
    discard setTimeout(proc() = 
      if tooltip.parentNode != nil:
        tooltip.parentNode.removeChild(tooltip)
    , 200)
    
    tooltipManager.activeTooltip = nil

proc clearTimers() =
  if tooltipManager.showTimer != 0:
    clearTimeout(tooltipManager.showTimer)
    tooltipManager.showTimer = 0
  if tooltipManager.hideTimer != 0:
    clearTimeout(tooltipManager.hideTimer)
    tooltipManager.hideTimer = 0

proc onMouseEnter(element: Element, config: TooltipConfig) =
  clearTimers()
  
  tooltipManager.showTimer = setTimeout(proc() = 
    showTooltip(element, config)
  , config.delay)

proc onMouseLeave() =
  clearTimers()
  
  tooltipManager.hideTimer = setTimeout(proc() = 
    hideTooltip()
  , 100)

proc addTooltip*(element: Element, text: cstring, position: TooltipPosition = tpAuto, delay: int = 500) =
  ## Add a simple tooltip to an element
  let config = TooltipConfig(
    text: text,
    position: position,
    delay: delay,
    maxWidth: 300,
    className: "",
    html: false
  )
  
  addTooltip(element, config)

proc addTooltip*(element: Element, config: TooltipConfig) =
  ## Add a tooltip with custom configuration
  let id = cstring($cast[int](element))
  
  # Remove existing tooltip if present
  if tooltipManager.tooltips.hasKey(id):
    removeTooltip(element)
  
  # Store tooltip reference
  tooltipManager.tooltips[id] = element
  
  # Add event listeners
  element.addEventListener("mouseenter", proc(e: Event) = 
    onMouseEnter(element, config)
  )
  
  element.addEventListener("mouseleave", proc(e: Event) = 
    onMouseLeave()
  )
  
  # Handle focus for accessibility
  element.addEventListener("focus", proc(e: Event) = 
    onMouseEnter(element, config)
  )
  
  element.addEventListener("blur", proc(e: Event) = 
    onMouseLeave()
  )

proc removeTooltip*(element: Element) =
  ## Remove tooltip from an element
  let id = cstring($cast[int](element))
  
  if tooltipManager.tooltips.hasKey(id):
    tooltipManager.tooltips.del(id)
    
    # Remove event listeners by cloning the element
    let newElement = element.cloneNode(true)
    if element.parentNode != nil:
      element.parentNode.replaceChild(newElement, element)

proc updateTooltipText*(element: Element, newText: cstring) =
  ## Update the text of an existing tooltip
  let id = cstring($cast[int](element))
  
  if tooltipManager.tooltips.hasKey(id):
    removeTooltip(element)
    addTooltip(element, newText)

proc initTooltips*() =
  ## Initialize the tooltip system
  tooltipManager = TooltipManager(
    tooltips: initTable[cstring, Element](),
    activeTooltip: nil,
    showTimer: 0,
    hideTimer: 0,
    config: TooltipConfig()
  )
  
  # Global escape key handler
  document.addEventListener("keydown", proc(e: Event) =
    let ke = KeyboardEvent(e)
    if ke.key == "Escape":
      hideTooltip()
  )
  
  # Hide tooltip when scrolling
  window.addEventListener("scroll", proc(e: Event) =
    hideTooltip()
  )
  
  # Hide tooltip when window is resized
  window.addEventListener("resize", proc(e: Event) =
    hideTooltip()
  )

# Utility procedures for common tooltip patterns
proc addSimpleTooltip*(selector: cstring, text: cstring) =
  ## Add tooltips to all elements matching a CSS selector
  let elements = document.querySelectorAll(selector)
  for i in 0..<elements.length:
    let element = Element(elements[i])
    addTooltip(element, text)

proc addTooltipFromAttribute*(selector: cstring, attribute: cstring = "data-tooltip") =
  ## Add tooltips using data attributes
  let elements = document.querySelectorAll(selector)
  for i in 0..<elements.length:
    let element = Element(elements[i])
    let tooltipText = element.getAttribute(attribute)
    if tooltipText != nil and tooltipText != "":
      addTooltip(element, tooltipText)

proc addRichTooltip*(element: Element, htmlContent: cstring, position: TooltipPosition = tpAuto) =
  ## Add a tooltip that supports HTML content
  let config = TooltipConfig(
    text: htmlContent,
    position: position,
    delay: 500,
    maxWidth: 400,
    className: "rich-tooltip",
    html: true
  )
  addTooltip(element, config)

# CSS styles to be added to your project
const tooltipCSS* = """
.aluminum-tooltip {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  line-height: 1.4;
}

.aluminum-tooltip.rich-tooltip {
  max-width: 400px;
  line-height: 1.5;
}

.aluminum-tooltip::after {
  content: '';
  position: absolute;
  width: 0;
  height: 0;
  border: 6px solid transparent;
  pointer-events: none;
}

/* Tooltip arrows - these would need to be positioned dynamically */
.aluminum-tooltip[data-position="top"]::after {
  top: 100%;
  left: 50%;
  margin-left: -6px;
  border-top-color: #333;
}

.aluminum-tooltip[data-position="bottom"]::after {
  bottom: 100%;
  left: 50%;
  margin-left: -6px;
  border-bottom-color: #333;
}

.aluminum-tooltip[data-position="left"]::after {
  left: 100%;
  top: 50%;
  margin-top: -6px;
  border-left-color: #333;
}

.aluminum-tooltip[data-position="right"]::after {
  right: 100%;
  top: 50%;
  margin-top: -6px;
  border-right-color: #333;
}
"""

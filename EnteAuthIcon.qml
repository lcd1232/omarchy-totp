import QtQuick
import QtQuick.Shapes
import qs.Commons

// Shield-and-keyhole mark in one colour, so it follows the theme like the
// built-in bar icons. Drawn on a 36x36 viewBox.
Item {
  id: root

  property real iconSize: Style.font.icon
  property color color: Color.foreground
  property real iconOpacity: 1.0

  width: iconSize
  height: iconSize
  implicitWidth: iconSize
  implicitHeight: iconSize

  Shape {
    width: 36
    height: 36
    scale: root.iconSize / 36
    transformOrigin: Item.TopLeft
    opacity: root.iconOpacity
    antialiasing: true
    preferredRendererType: Shape.CurveRenderer

    ShapePath {
      fillColor: root.color
      fillRule: ShapePath.OddEvenFill
      strokeWidth: -1
      strokeColor: "transparent"
      PathSvg { path: "M18 2 L31 7 V17 C31 25.5 25.6 31.6 18 34 C10.4 31.6 5 25.5 5 17 V7 Z" }
      PathSvg { path: "M18 11 A4 4 0 0 0 16.2 18.6 L15 25 H21 L19.8 18.6 A4 4 0 0 0 18 11 Z" }
    }
  }
}

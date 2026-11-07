pragma Singleton

import QtQuick

QtObject {
    property QtObject color: QtObject {
        readonly property color transparent: 'transparent'

        readonly property color textPrimary: '#FAFAFA'
        readonly property color textSecondary: '#E4E4E7'
        readonly property color textTertiary: '#A1A1AA'
        readonly property color textQuaternary: '#86868F'
        readonly property color textInverted: '#09090B'
        readonly property color textAccent: '#FDBA74'
        readonly property color textInfoInverse: '#0369A1'
        readonly property color textStaticWhite: '#FFFFFF'

        readonly property color bgBase: '#101012'
        readonly property color bgSurface: '#18181B'
        readonly property color bgSurfaceAlt: '#1F1F23'
        readonly property color bgSheet: '#313136'
        readonly property color bgPanel: '#3F3F46'
        readonly property color bgPanelAlt: '#52525B'
        readonly property color bgOverlay: '#8009090B'
        readonly property color bgStateLayer: '#14FAFAFA'
        readonly property color bgStateLayerPressed: '#1AFAFAFA'
        readonly property color bgStateLayerAccent: '#14FDBA74'
        readonly property color bgSurfaceInverse: '#E4E4E7'
        readonly property color bgSurfaceInverseAlt: '#D4D4D8'
        readonly property color bgControlTrack: '#1F1F23'
        readonly property color bgField: '#1F1F23'
        readonly property color bgSelected: '#1F1F23'
        readonly property color bgAccentSubtle: '#4DD97706'
        readonly property color bgStaticWhite: '#FFFFFF'

        readonly property color bgAction: '#E4E4E7'
        readonly property color bgActionHover: '#D4D4D8'
        readonly property color bgActionPress: '#A1A1AA'

        readonly property color borderFaint: '#313136'
        readonly property color borderSoft: '#3F3F46'
        readonly property color borderMedium: '#52525B'
        readonly property color borderBold: '#A1A1AA'
        readonly property color borderEmphasis: '#E4E4E7'
        readonly property color borderAccent: '#FDBA74'
        readonly property color borderField: '#52525B'
        readonly property color borderFocus: '#E4E4E7'

        readonly property color accentLight: '#FDBA74'
        readonly property color accentDefault: '#F59E0B'
        readonly property color accentDark: '#D97706'
        readonly property color accentDeep: '#78350F'

        readonly property color statusDestructive: '#F87171'
        readonly property color statusWarning: '#EAB308'
        readonly property color statusSuccess: '#4ADE80'

        readonly property color promoRecommendation: '#A78BFA'
        readonly property color promoUpdate: '#38BDF8'
        readonly property color promoOverlay: '#148B5CF6'
        readonly property color promoPink: '#DB2777'
        readonly property color promoPinkDeep: '#9D174D'

        readonly property color iconDefault: '#E4E4E7'
        readonly property color iconSecondary: '#A1A1AA'
        readonly property color iconTertiary: '#3F3F46'
        readonly property color iconInverted: '#09090B'

        readonly property color shadowLayer1: '#26000000'
        readonly property color shadowLayer2: '#4D000000'
        readonly property color shadowGlow: '#FBB751'

        // Preserve fork-only color contracts without changing upstream tokens.
        readonly property color paleGray: '#D7D8DB'
        readonly property color lightGray: '#C1C2C5'
        readonly property color mutedGray: '#878B91'
        readonly property color charcoalGray: '#494B50'
        readonly property color slateGray: '#2C2D30'
        readonly property color onyxBlack: '#1C1D21'
        readonly property color midnightBlack: '#0E0E11'
        readonly property color goldenApricot: goldenApricotString
        readonly property color benefitsPanelBackground: '#1C1C1E'
        readonly property color softViolet: '#A87BE2'
        readonly property color burntOrange: '#A85809'
        readonly property color mutedBrown: '#84603D'
        readonly property color richBrown: '#633303'
        readonly property color deepBrown: '#402102'
        readonly property color vibrantRed: '#EB5757'
        readonly property color vibrantGreen: '#3FBF6B'
        readonly property color deepMagenta: '#950051'
        readonly property color darkCharcoal: '#261E1A'
        readonly property color pearlGray: '#EAEAEC'
        readonly property color sheerWhite: Qt.rgba(1, 1, 1, 0.12)
        readonly property color translucentWhite: Qt.rgba(1, 1, 1, 0.08)
        readonly property color barelyTranslucentWhite: Qt.rgba(1, 1, 1, 0.05)
        readonly property color translucentMidnightBlack: Qt.rgba(14/255, 14/255, 17/255, 0.8)
        readonly property color softGoldenApricot: Qt.rgba(251/255, 178/255, 106/255, 0.3)
        readonly property color mistyGray: Qt.rgba(215/255, 216/255, 219/255, 0.8)
        readonly property color cloudyGray: Qt.rgba(215/255, 216/255, 219/255, 0.65)
        readonly property color translucentRichBrown: Qt.rgba(99/255, 51/255, 3/255, 0.26)
        readonly property color translucentSlateGray: Qt.rgba(85/255, 86/255, 92/255, 0.13)
        readonly property color translucentOnyxBlack: Qt.rgba(28/255, 29/255, 33/255, 0.13)
        readonly property string goldenApricotString: '#FBB26A'
        readonly property color backgroundBase: '#101012'
        readonly property color surfaceBase: '#18181B'
        readonly property color surfaceHovered: '#232327'
        readonly property color surfacePressed: '#2C2D30'
        readonly property color surfaceInverse: '#E4E4E7'
        readonly property color surfaceInverseHovered: '#D4D4D8'
        readonly property color surfaceInversePressed: '#A1A1AA'
        readonly property color accentSuccess: '#4ADE80'
        readonly property color accentWarning: '#EAB308'
    }
}

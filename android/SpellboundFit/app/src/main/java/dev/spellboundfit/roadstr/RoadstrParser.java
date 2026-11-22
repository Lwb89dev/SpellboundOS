package dev.spellboundfit.roadstr;

import dev.spellboundfit.protocol.Protocol;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parses English and Italian Roadstr / turn-by-turn navigation notifications
 * into structured NavInstruction frames for SpellboundOS.
 */
public final class RoadstrParser {
    private static final Pattern DIST_RE = Pattern.compile(
            "(\\d+(?:[.,]\\d+)?)\\s*(km|m)\\b", Pattern.CASE_INSENSITIVE);
    private static final Pattern ETA_RE = Pattern.compile(
            "(?:eta|arrivo)[^0-9]*(\\d+)\\s*(?:min|m\\b)", Pattern.CASE_INSENSITIVE);
    private static final Pattern EXIT_RE = Pattern.compile(
            "(\\d+)(?:st|nd|rd|th|a|\\u00b0)?\\s*(?:exit|uscita)", Pattern.CASE_INSENSITIVE);
    private static final Pattern STREET_RE = Pattern.compile(
            "\\b(?:onto|on|su|verso|towards?)\\s+([^\\u2022|\\n()]+)", Pattern.CASE_INSENSITIVE);
    private static final Pattern TRAILING_ETA_RE = Pattern.compile(
            "\\s*(?:eta|arrivo)\\b.*$", Pattern.CASE_INSENSITIVE);

    private RoadstrParser() {}

    public static final class NavInstruction {
        public final int maneuver;
        public final int roundaboutExit;
        public final long distanceMeters;
        public final int etaMin;
        public final String street;

        public NavInstruction(int maneuver, int roundaboutExit,
                              long distanceMeters, int etaMin, String street) {
            this.maneuver = maneuver;
            this.roundaboutExit = roundaboutExit;
            this.distanceMeters = distanceMeters;
            this.etaMin = etaMin;
            this.street = street;
        }

        public byte[] toFrame(int seq) {
            return Protocol.encodeNavUpdate(
                    seq, maneuver, roundaboutExit, distanceMeters, etaMin, street, "");
        }
    }

    private static int detectManeuver(String text) {
        String low = text.toLowerCase(Locale.ROOT);
        if (containsAny(low, "arrived", "destination", "arrivato", "destinazione")) {
            return Protocol.NAV_ARRIVE;
        }
        if (containsAny(low, "roundabout", "rotonda", "rotatoria")) {
            return Protocol.NAV_ROUNDABOUT;
        }
        if (containsAny(low, "u-turn", "inversione")) {
            return Protocol.NAV_UTURN;
        }
        if (containsAny(low, "sharp left", "stretta a sinistra")) {
            return Protocol.NAV_SHARP_LEFT;
        }
        if (containsAny(low, "slight left", "leggermente a sinistra", "tieni la sinistra")) {
            return Protocol.NAV_SLIGHT_LEFT;
        }
        if (containsAny(low, "left", "sinistra")) {
            return Protocol.NAV_LEFT;
        }
        if (containsAny(low, "sharp right", "stretta a destra")) {
            return Protocol.NAV_SHARP_RIGHT;
        }
        if (containsAny(low, "slight right", "leggermente a destra", "tieni la destra")) {
            return Protocol.NAV_SLIGHT_RIGHT;
        }
        if (containsAny(low, "right", "destra")) {
            return Protocol.NAV_RIGHT;
        }
        if (containsAny(low, "straight", "continue", "prosegui", "dritto")) {
            return Protocol.NAV_STRAIGHT;
        }
        return Protocol.NAV_NONE;
    }

    private static boolean containsAny(String haystack, String... needles) {
        for (String n : needles) {
            if (haystack.contains(n)) return true;
        }
        return false;
    }

    public static NavInstruction parse(String title, String body) {
        String t = title == null ? "" : title.trim();
        String b = body == null ? "" : body.trim();
        String combined = (t + " " + b).trim();
        int maneuver = detectManeuver(combined);
        if (maneuver == Protocol.NAV_NONE) {
            return null;
        }

        long distM = 0;
        Matcher dm = DIST_RE.matcher(combined);
        if (dm.find()) {
            double val = Double.parseDouble(dm.group(1).replace(',', '.'));
            String unit = dm.group(2).toLowerCase(Locale.ROOT);
            distM = "km".equals(unit) ? Math.round(val * 1000.0) : Math.round(val);
        }

        int eta = 0;
        Matcher em = ETA_RE.matcher(combined);
        if (em.find()) {
            eta = Integer.parseInt(em.group(1));
        }

        int exit = 0;
        if (maneuver == Protocol.NAV_ROUNDABOUT) {
            Matcher xm = EXIT_RE.matcher(combined);
            if (xm.find()) {
                exit = Integer.parseInt(xm.group(1));
            }
        }

        String street = "";
        Matcher sm = STREET_RE.matcher(b);
        if (!sm.find()) {
            sm = STREET_RE.matcher(t);
            if (!sm.find()) {
                sm = null;
            }
        }
        if (sm != null) {
            street = TRAILING_ETA_RE.matcher(sm.group(1)).replaceAll("").trim();
            street = trimPunct(street);
        }
        if (street.isEmpty()) {
            street = t;
        }
        if (street.length() > 63) {
            street = street.substring(0, 63);
        }
        return new NavInstruction(maneuver, exit, distM, eta, street);
    }

    private static String trimPunct(String s) {
        int start = 0;
        int end = s.length();
        while (start < end && " -.,:".indexOf(s.charAt(start)) >= 0) start++;
        while (end > start && " -.,:".indexOf(s.charAt(end - 1)) >= 0) end--;
        return s.substring(start, end);
    }
}

package utils;

import java.text.Normalizer;
import java.util.regex.Pattern;

public class Utils {

    public static String cleanString(String s) {
        String upperString = s.toUpperCase();
        String stringC = s.replace("Ç", "C");
        String normalizedString = Normalizer.normalize(s, Normalizer.Form.NFD);
        Pattern pattern = Pattern.compile("\\p{InCombiningDiacriticalMarks}+");
        String cleanString = pattern.matcher(normalizedString).replaceAll("");

        return cleanString;
    }

}
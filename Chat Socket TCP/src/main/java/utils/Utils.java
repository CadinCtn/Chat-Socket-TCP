package utils;

import java.text.Normalizer;
import java.util.regex.Pattern;

public class Utils {

    public static String cleanString(String s) {

        String normalizedString = Normalizer.normalize(
                s.toUpperCase(),
                Normalizer.Form.NFD
        );

        Pattern pattern = Pattern.compile("\\p{InCombiningDiacriticalMarks}+");

        return pattern.matcher(normalizedString)
                .replaceAll("")
                .replace("Ç", "C");
    }

}
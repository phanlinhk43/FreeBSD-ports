<?php
/**
* Polish (pl) translation file.
* Based on phpScheduleIt translation file.
* This also serves as the base translation file from which to derive
*  all other translations.
*
* @author Samuel Tran <stran2005@users.sourceforge.net>
* @author Brian Wong <bwsource@users.sourceforge.net>
* @author Nicolas Peyrussie <peyrouz@users.sourceforge.net>
* @version 04-03-07
* @package Languages
*
* Copyright (C) 2005 - 2007 MailZu
* License: GPL, see LICENSE
*
* $Id$
*/
///////////////////////////////////////////////////////////
// INSTRUCTIONS
///////////////////////////////////////////////////////////
// This file contains all of the strings that are used throughout phpScheduleit.
// Please save the translated file as '2 letter language code'.lang.php.  For example, en.lang.php.
// 
// To make phpScheduleIt available in another language, simply translate each
//  of the following strings into the appropriate one for the language.  If there
//  is no direct translation, please provide the closest translation.  Please be sure
//  to make the proper additions the /config/langs.php file (instructions are in the file).
//  Also, please add a help translation for your language using en.help.php as a base.
//
// You will probably keep all sprintf (%s) tags in their current place.  These tags
//  are there as a substitution placeholder.  Please check the output after translating
//  to be sure that the sentences make sense.
//
// + Please use single quotes ' around all $strings.  If you need to use the ' character, please enter it as \'
// + Please use double quotes " around all $email.  If you need to use the " character, please enter it as \"
//
// + For all $dates please use the PHP strftime() syntax
//    http://us2.php.net/manual/en/function.strftime.php
//
// + Non-intuitive parts of this file will be explained with comments.  If you
//    have any questions, please email lqqkout13@users.sourceforge.net
//    or post questions in the Developers forum on SourceForge
//    http://sourceforge.net/forum/forum.php?forum_id=331297
///////////////////////////////////////////////////////////

////////////////////////////////
/* Do not modify this section */
////////////////////////////////
global $strings;			  //
global $email;				  //
global $dates;				  //
global $charset;			  //
global $letters;			  //
global $days_full;			  //
global $days_abbr;			  //
global $days_two;			  //
global $days_letter;		  //
global $months_full;		  //
global $months_abbr;		  //
global $days_letter;		  //
/******************************/

// Charset for this language
// 'iso-8859-1' will work for most languages
$charset = 'utf-8';

/***
  DAY NAMES
  All of these arrays MUST start with Sunday as the first element 
   and go through the seven day week, ending on Saturday
***/
// The full day name
$days_full = array('Niedziela', 'Poniedzia??ek', 'Wtorek', '??roda', 'Czwartek', 'Pi??tek', 'Sobota');
// The three letter abbreviation
$days_abbr = array('Nie', 'Pon', 'Wto', '??ro', 'Czw', 'Pi??', 'Sob');
// The two letter abbreviation
$days_two  = array('Nd', 'Pn', 'Wt', '??r', 'Cz', 'Pi', 'So');
// The one letter abbreviation
$days_letter = array('N', 'P', 'W', '??', 'C', 'T', 'S');

/***
  MONTH NAMES
  All of these arrays MUST start with January as the first element
   and go through the twelve months of the year, ending on December
***/
// The full month name
$months_full = array('Stycze??', 'Luty', 'Marzec', 'Kwiecie??', 'Maj', 'Czerwiec', 'Lipiec', 'Sierpie??', 'Wrzesie??', 'Pa??dziernik', 'Listopad', 'Grudzie??');
// The three letter month name
$months_abbr = array('Sty', 'Lut', 'Mar', 'Kwi', 'Maj', 'Cze', 'Lip', 'Sie', 'Wrz', 'Pa??', 'Lis', 'Gru');

// All letters of the alphabet starting with A and ending with Z
$letters = array ('A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z');

/***
  DATE FORMATTING
  All of the date formatting must use the PHP strftime() syntax
  You can include any text/HTML formatting in the translation
***/
// General date formatting used for all date display unless otherwise noted
$dates['general_date'] = '%d/%m/%Y';
// General datetime formatting used for all datetime display unless otherwise noted
// The hour:minute:second will always follow this format
$dates['general_datetime'] = '%d/%m/%Y @';
$dates['header'] = '%A, %B %d, %Y';

/***
  STRING TRANSLATIONS
  All of these strings should be translated from the English value (right side of the equals sign) to the new language.
  - Please keep the keys (between the [] brackets) as they are.  The keys will not always be the same as the value.
  - Please keep the sprintf formatting (%s) placeholders where they are unless you are sure it needs to be moved.
  - Please keep the HTML and punctuation as-is unless you know that you want to change it.
***/
$strings['hours'] = 'godziny';
$strings['minutes'] = 'minuty';
// The common abbreviation to hint that a user should enter the month as 2 digits
$strings['mm'] = 'mm';
// The common abbreviation to hint that a user should enter the day as 2 digits
$strings['dd'] = 'dd';
// The common abbreviation to hint that a user should enter the year as 4 digits
$strings['yyyy'] = 'yyyy';
$strings['am'] = 'am';
$strings['pm'] = 'pm';

$strings['Administrator'] = 'Administrator';
$strings['Welcome Back'] = '%s, witaj ponownie';
$strings['Log Out'] = 'Wyloguj';
$strings['Help'] = 'Pomoc';

$strings['Admin Email'] = 'Email administratora';

$strings['Default'] = 'Domy??lny';
$strings['Reset'] = 'Reset';
$strings['Edit'] = 'Edytuj';
$strings['Delete'] = 'Skasuj';
$strings['Cancel'] = 'Anuluj';
$strings['View'] = 'Podgl??d';
$strings['Modify'] = 'Modyfikacja';
$strings['Save'] = 'Zachowaj';
$strings['Back'] = 'Powr??t';
$strings['BackMessageIndex'] = 'Powr??t do Wiadomo??ci';
$strings['ToggleHeaders'] = 'Prze????cz nag????wki';
$strings['ViewOriginal'] = 'Obejrzyj w oryginale';
$strings['Next'] = 'Nast??pna';
$strings['Close Window'] = 'Zamknij okno';
$strings['Search'] = 'Szukaj';
$strings['Clear'] = 'Wyczy????';

$strings['Days to Show'] = 'Dni do pokazania';
$strings['Reservation Offset'] = 'Reservation Offset';
$strings['Hidden'] = 'Ukryte';
$strings['Show Summary'] = 'Poka?? podsumowanie';
$strings['Add Schedule'] = 'Dodaj Schedule';
$strings['Edit Schedule'] = 'Edytuj Schedule';
$strings['No'] = 'Nie';
$strings['Yes'] = 'Tak';
$strings['Name'] = 'Nazwa';
$strings['First Name'] = 'Imi??';
$strings['Last Name'] = 'Nazwisko';
$strings['Resource Name'] = 'Nazwa ??r??d??a';
$strings['Email'] = 'Email';
$strings['Institution'] = 'Instytucja';
$strings['Phone'] = 'Telefon';
$strings['Password'] = 'Has??o';
$strings['Permissions'] = 'Uprawnienia';
$strings['View information about'] = 'Zobacz informacj?? o %s %s';
$strings['Send email to'] = 'Wy??lij email do %s %s';
$strings['Reset password for'] = 'Reset has??a dla %s %s';
$strings['Edit permissions for'] = 'Edycja uprawnie?? dla %s %s';
$strings['Position'] = 'Pozycja';
$strings['Password (6 char min)'] = 'Has??o (minimum %s znak??w)';	// @since 1.1.0
$strings['Re-Enter Password'] = 'Wprowad?? has??o ponownie';

$strings['Date'] = 'Data';
$strings['Email Users'] = 'Wy??lij email do u??ytkownik??w';
$strings['Subject'] = 'Temat';
$strings['Message'] = 'Wiadomo????';
$strings['Send Email'] = 'Wy??lij Email';
$strings['problem sending email'] = 'Niestety wyst??pi?? b????d podczas wysy??ania emaila. Prosz?? spr??bowa?? ponownie p????niej.';
$strings['The email sent successfully.'] = 'Wys??anie emaila zako??czone sukcesem.';
$strings['Email address'] = 'Adres email';
$strings['Please Log In'] = 'Prosz?? si?? zalogowa??';
$strings['Keep me logged in'] = 'Pami??taj moje dane logowania <br/>(wymagane ciasteczka)';
$strings['Password'] = 'Has??o';
$strings['Log In'] = 'Zaloguj';
$strings['Get online help'] = 'Dost??p do pomocy';
$strings['Language'] = 'J??zyk';
$strings['(Default)'] = '(Domy??lnie)';

$strings['Email Administrator'] = 'Wy??lij email do administrator';

$strings['N/A'] = 'Niedost??pne';
$strings['Summary'] = 'Podsumowanie';

$strings['View stats for schedule'] = 'Zobacz statystyki dla wykazu:';
$strings['At A Glance'] = 'W skr??cie';
$strings['Total Users'] = 'Wszystkich u??ytkownik??w:';
$strings['Total Resources'] = 'Wszystkich zasob??w:';
$strings['Total Reservations'] = 'Wszystkich Rezerwacji:';
$strings['Max Reservation'] = 'Maksimum Rezerwacji:';
$strings['Min Reservation'] = 'Minimum Rezerwacji:';
$strings['Avg Reservation'] = '??rednio Rezerwacji:';
$strings['Most Active Resource'] = 'Najbardziej aktywne ??r??d??a:';
$strings['Most Active User'] = 'Najbardziej aktywni u??ytkownicy:';
$strings['System Stats'] = 'Statystyki systemowe';
$strings['phpScheduleIt version'] = 'Wersja phpScheduleIt:';
$strings['Database backend'] = 'Baza danych:';
$strings['Database name'] = 'Nazwa bazy danych:';
$strings['PHP version'] = 'Wersja PHP:';
$strings['Server OS'] = 'System operacyjny serwera:';
$strings['Server name'] = 'Nazwa serwera:';
$strings['phpScheduleIt root directory'] = 'Katalog g????wny (root) phpScheduleIt:';
$strings['Using permissions'] = 'Using permissions:';
$strings['Using logging'] = 'Using logging:';
$strings['Log file'] = 'Plik logu:';
$strings['Admin email address'] = 'Adres email administracyjny:';
$strings['Tech email address'] = 'Adres email techniczny:';
$strings['CC email addresses'] = 'Adresy email do Cc (do wiadomo??ci):';
$strings['Reservation start time'] = 'Czas rozpocz??cia rezerwacji:';
$strings['Reservation end time'] = 'Czas zako??czenia rezerwacji:';
$strings['Days shown at a time'] = 'Pokazana liczba dni:';
$strings['Reservations'] = 'Rezerwacje';
$strings['Return to top'] = 'Powr??t na pocz??tek';
$strings['for'] = 'dla';

$strings['Per page'] = 'na stron??:';
$strings['Page'] = 'Strona:';

$strings['You are not logged in!'] = 'Nie jeste?? zalogowany!';

$strings['Setup'] = 'Setup';
$strings['Invalid User Name/Password.'] = 'Niepoprawny login/has??o.';

$strings['Valid username is required'] = 'Wymagana poprawna nazwa u??ytkownika';

$strings['Close'] = 'Zamknij';

$strings['Admin'] = 'Admin';

$strings['My Quick Links'] = 'Moje szybkie odno??niki';

$strings['Go to first page'] = 'Id?? na pierwsz?? stron??';
$strings['Go to last page'] = 'Id?? na ostatni?? stron??';
$strings['Sort by descending order'] = 'Uporz??dkuj malej??co';
$strings['Sort by ascending order'] = 'Uporz??dkuj rosn??co';
$strings['Spam Quarantine'] = 'Kwarantanna spam??w';
$strings['Message View'] = 'Podgl??d wiadomo??ci';
$strings['Attachment Quarantine'] = 'Kwarantanna za????cznik??w';
$strings['No such content type'] = 'Nierozpoznana zawarto???? (content type)';
$strings['No message was selected'] = 'Nie wybrano wiadomo??ci...';
$strings['Unknown action type'] = 'Nieznany rodzaj akcji...';
$strings['A problem occured when trying to release the following messages'] = 'Wyst??pi?? b????d w trakcie uwalniania wiadomo??ci';
$strings['A problem occured when trying to delete the following messages'] = 'Wyst??pi?? b????d w trakcie kasowania wiadomo??ci';
$strings['Please release the following messages'] = 'Prosz?? uwolni?? nast??puj??ce wiadomo??ci';
$strings['To'] = 'Do';
$strings['From'] = 'Od';
$strings['Subject'] = 'Temat';
$strings['Date'] = 'Data';
$strings['Score'] = 'Punkty';
$strings['Mail ID'] = 'ID wiadomo??ci';
$strings['Status'] = 'Status';
$strings['Print'] = 'Drukuj';
$strings['CloseWindow'] = 'Zamknij';
$strings['Unknown server type'] = 'Nieznany type serwera...';
$strings['Showing messages'] = "Wy??wietlenie wiadomo??ci %s do %s &nbsp;&nbsp; (%s wszystkich)\r\n";
$strings['View this message'] = 'Zobacz wiadomo????';
$strings['Message Unavailable'] = 'Wiadomo???? niedost??pna';
$strings['My Quarantine'] = 'Moja kwarantanna';
$strings['Site Quarantine'] = 'Kwarantanna systemu';
$strings['Message Processing'] = 'Przetwarzanie wiadomo??ci';
$strings['Quarantine Summary'] = 'Podsumowanie kwarantanny';
$strings['Site Quarantine Summary'] = 'Podsumowanie kwarantanny systemu';
$strings['Login'] = 'Login';
$strings['spam(s)'] = 'spam(??w)';
$strings['attachment(s)'] = 'za????cznik(??w)';
$strings['pending release request(s)'] = 'przetwarzanie ????dania(??) uwolnienia';
$strings['virus(es)'] = 'wirus(??w)';
$strings['bad header(s)'] = 'z??y(ch) nag????w-ek/k??w';
$strings['You have to type some text'] = 'Musisz poda?? jakikolwiek tekst';
$strings['Release'] = 'Zwolnij';
$strings['Release/Request release'] = 'Zwolnij wiadomo??ci oczekuj??ce w kolejce';
$strings['Request release'] = 'Pro??ba o zwolnienie';
$strings['Delete'] = 'Skasuj';
$strings['Delete All'] = 'Skasuj wszystko';
$strings['Send report and go back'] = 'Wy????anie raportu i powr??t';
$strings['Go back'] = "Powr??t";
$strings['Select All'] = "Wybierz wszystko";
$strings['Clear All'] = "Wyczy???? wszystko";
$strings['Access Denied'] = "Dost??p zabroniony";
$strings['My Pending Requests'] = "My Pending Requests";
$strings['Site Pending Requests'] = "Site Pending Requests";
$strings['Cancel Request'] = "Anuluj pro??b??";
$strings['User is not allowed to login'] = "Brak uprawnie?? do zalogowania dla u??ytkownika";
$strings['Authentication successful'] = "Uwierzytelnienie poprawne";
$strings['Authentication failed'] = "Uwierzytelnienie niepoprawne";
$strings['LDAP connection failed'] = "Po????czenie LDAP/AD nie powiod??o si??";
$strings['Logout successful'] = "Wylogowanie poprawne";
$strings['IMAP Authentication: no match'] = "IMAP Authentication: no match";
$strings['Search for messages whose:'] = "Szukaj wiadomo??ci, kt??re:";
$strings['Content Type'] = "Content Type";
$strings['Clear search results'] = "Wyczy???? wyniki wyszukiwania";
$strings['contains'] = "zawiera";
$strings['doesn\'t contain'] = "nie zawiera";
$strings['equals'] = "";
$strings['doesn\'t equal'] = "r????ny od";
$strings['All'] = "Wszystko";
$strings['Spam'] = "Spam";
$strings['Banned'] = "Niepoprawny za????cznik";
$strings['Virus'] = "Wirus";
$strings['Viruses'] = "Viruses";
$strings['Bad Header'] = "Bad Header";
$strings['Bad Headers'] = "Bad Headers";
$strings['Pending Requests'] = "Pending Requests";
$strings['last'] = "ostatnie";
$strings['first'] = "pierwsze";
$strings['previous'] = "poprzedni";
$strings['There was an error executing your query'] = 'There was an error executing your query:';
$strings['There are no matching records.'] = 'There are no matching records.';
$strings['Domain'] = 'Domena';
$strings['Total'] = 'Wszystko';
$strings['X-Amavis-Alert'] = 'X-Amavis-Alert';
$strings['Loading Summary...'] = 'Loading Summary...';
$strings['Retrieving Messages...'] = 'Retrieving Messages...';
?>

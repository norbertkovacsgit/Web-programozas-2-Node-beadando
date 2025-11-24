-- phpMyAdmin SQL Dump
-- version 5.2.1
-- https://www.phpmyadmin.net/
--
-- Gép: 127.0.0.1
-- Létrehozás ideje: 2025. Nov 24. 20:50
-- Kiszolgáló verziója: 10.4.32-MariaDB
-- PHP verzió: 8.2.12

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Adatbázis: `user`
--

-- --------------------------------------------------------

--
-- Tábla szerkezet ehhez a táblához `contact_messages`
--

CREATE TABLE `contact_messages` (
  `id` int(11) NOT NULL,
  `user_id` int(11) DEFAULT NULL,
  `name` varchar(100) NOT NULL,
  `email` varchar(255) NOT NULL,
  `subject` varchar(200) NOT NULL,
  `message` text NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- A tábla adatainak kiíratása `contact_messages`
--

INSERT INTO `contact_messages` (`id`, `user_id`, `name`, `email`, `subject`, `message`, `created_at`) VALUES
(4, 1, '1', 'valami@valami.hu', 'tárgy1', 'üzenet1', '2025-11-13 07:47:55'),
(5, 1, '2', 'valami2@valami.hu', 'tárgy2', 'üzenet2', '2025-11-13 07:48:06'),
(6, 1, '3', 'valami3@valami.hu', 'tárgy3', 'üzenet3', '2025-11-13 07:48:18'),
(7, 1, '4', 'valami4@valami.hu', 'tárgy4', 'üzenet4', '2025-11-13 07:48:34'),
(8, 1, '5', 'valami5@valami.hu', 'tárgy5', 'üzenet5', '2025-11-13 07:48:49'),
(9, NULL, '6', 'valami6@valami.hu', 'tárgy6', 'üzenet6', '2025-11-13 07:49:44'),
(10, NULL, '7', 'valami7@valami.hu', 'tárgy7', 'üzenet7', '2025-11-13 07:50:03'),
(11, NULL, '8', 'valami8@valami.hu', 'tárgy8', 'üzenet8', '2025-11-13 07:50:15'),
(12, NULL, '9', 'valami9@valami.hu', 'tárgy9', 'üzenet9', '2025-11-13 07:50:29'),
(13, 7, '10', 'valami10@valami.hu', 'tárgy10', 'üzenet10', '2025-11-13 07:52:01'),
(14, 7, '11', 'valami11@valami.hu', 'tárgy11', 'üzenet11', '2025-11-13 07:52:12'),
(15, 7, '12', 'valami12@valami.hu', 'ez egy nagyon hosszú tárgy lesz, hogy tudjam tesztelni a sortöréseket az üzenetek oldalon', 'Lorem Ipsum\r\n\"Neque porro quisquam est qui dolorem ipsum quia dolor sit amet, consectetur, adipisci velit...\"\r\n\"There is no one who loves pain itself, who seeks after it and wants to have it, simply because it is pain...\"', '2025-11-13 07:55:37'),
(16, 1, 'norbi', 'valami@valami.hu', 'ez a final tárgy', 'üzenet a feltöltés előtt', '2025-11-14 11:28:41');

-- --------------------------------------------------------

--
-- Tábla szerkezet ehhez a táblához `gep`
--

CREATE TABLE `gep` (
  `id` int(11) NOT NULL,
  `gyarto` varchar(50) NOT NULL,
  `tipus` varchar(120) NOT NULL,
  `kijelzo` decimal(4,1) NOT NULL,
  `memoria` int(11) NOT NULL,
  `merevlemez` int(11) NOT NULL,
  `videovezerlo` varchar(120) NOT NULL,
  `ar` int(11) NOT NULL,
  `processzorid` int(11) NOT NULL,
  `oprendszerid` int(11) NOT NULL,
  `db` int(11) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- A tábla adatainak kiíratása `gep`
--

INSERT INTO `gep` (`id`, `gyarto`, `tipus`, `kijelzo`, `memoria`, `merevlemez`, `videovezerlo`, `ar`, `processzorid`, `oprendszerid`, `db`) VALUES
(1, 'HP', 'COMPAQ 615 NX556EA', 15.6, 1024, 160, 'ATi Mobility Radeon HD3200 256MB', 95120, 1, 1, 0),
(2, 'ASUS', 'K51AC-SX001D', 15.6, 2048, 250, 'ATi Mobility Radeon HD3200 256MB', 101200, 1, 8, 0),
(3, 'HP', 'COMPAQ 615 NX560EA', 15.6, 2048, 320, 'ATi Mobility Radeon HD3200 256MB', 114800, 1, 4, 0),
(4, 'HP', 'Pavilion DV6-1110EH NL956EA', 15.6, 3072, 250, 'ATi Mobility Radeon HD4530 512MB', 167920, 1, 6, 3),
(5, 'ACER', 'Aspire 5536G-642G25MN', 15.6, 2048, 250, 'ATi Mobility Radeon HD4570 512MB', 111920, 1, 2, 3),
(6, 'ACER', 'Aspire 5536G-643G32MN', 15.6, 3072, 320, 'ATi Mobility Radeon HD4570 512MB', 117520, 1, 2, 2),
(7, 'MSI', 'X410-019HU', 14.0, 2048, 320, 'ATI Radeon Xpress 1250', 111920, 4, 6, 4),
(8, 'ASUS', 'F83T-VX005X', 14.0, 4096, 500, 'ATi Mobility Radeon HD4570 512MB', 115920, 4, 8, 1),
(9, 'MSI', 'VR630XL-004HU', 16.0, 2048, 320, 'NVIDIA GeForce Go 9100M-GS', 90800, 5, 1, 1),
(10, 'ASUS', 'N60DP-JX012V', 16.0, 4096, 500, 'ATi Mobility Radeon HD4670 512MB', 183920, 6, 10, 4),
(11, 'ASUS', 'K50AB-SX045D', 15.6, 4096, 500, 'ATi Mobility Radeon HD4570 512MB', 134320, 7, 8, 5),
(12, 'FUJITSU', 'Amilo Sa3650', 13.3, 2048, 250, 'ATi Mobility Radeon HD3200 256MB', 223920, 8, 6, 4),
(13, 'MSI', 'WIND U200-064HU', 12.0, 2048, 320, 'Intel Graphics X4500M / 256MB', 112400, 51, 6, 3),
(14, 'ACER', 'eMachine E525-901G16Mi', 15.6, 1024, 160, 'Intel Graphics 4500MHD ', 82800, 10, 2, 0),
(15, 'DELL', 'Inspiron 1545-106208 RED', 15.6, 1024, 160, 'Intel Graphics 4500MHD ', 103120, 10, 2, 3),
(16, 'TOSHIBA', 'Satellite L500-1EN', 15.6, 2048, 320, 'Intel Graphics X4500M / 256MB', 118800, 10, 1, 1),
(17, 'MSI', 'CR500X-012HU', 15.6, 2048, 320, 'NVIDIA GeForce Go 8200M 128MB', 94800, 10, 1, 1),
(18, 'MSI', 'CR500X-008HU', 15.6, 4096, 320, 'NVIDIA GeForce Go 8200M 128MB', 95920, 10, 1, 3),
(19, 'LENOVO', 'SL500 2746P5G', 15.4, 1024, 160, 'NVIDIA GeForce Go 9300M 256MB', 139920, 12, 4, 0),
(20, 'TOSHIBA', 'Satellite L300-24P', 15.4, 2048, 160, 'Intel Graphics 4500MHD', 98000, 12, 1, 0),
(21, 'MSI', 'VR603X-094HU', 15.4, 4096, 320, 'Intel Graphics 4500MHD', 99600, 12, 1, 5),
(22, 'HP', 'ProBook 4510s NX435EA', 15.6, 2048, 250, 'Intel Graphics 4500MHD', 111920, 12, 1, 1),
(23, 'FUJITSU', 'Esprimo V6535', 15.4, 1024, 160, 'Intel Graphics 4500MHD ', 95920, 13, 2, 4),
(24, 'LENOVO', 'IdeaPad G550L 59-026377', 15.6, 1024, 160, 'Intel Graphics 4500MHD', 94320, 14, 4, 5),
(25, 'HP', 'Presario CQ61-200SH NZ890EA', 15.6, 3072, 320, 'Intel Graphics 4500MHD', 127120, 14, 4, 3),
(26, 'ACER', 'eMachine E525-302G25Mi', 15.6, 2048, 250, 'Intel Graphics 4500MHD ', 89200, 14, 2, 0),
(27, 'HP', 'ProBook 4510s NX668EA', 15.6, 2048, 250, 'Intel Graphics 4500MHD ', 113520, 14, 2, 3),
(28, 'HP', 'ProBook 4310s NX580EA', 13.3, 1024, 160, 'Intel Graphics 4500MHD ', 119920, 14, 2, 3),
(29, 'ASUS', 'K50IJ-SX036L', 15.6, 2048, 250, 'Intel Graphics X4500M', 94320, 14, 8, 2),
(30, 'ASUS', 'K50IJ-SX153L', 15.6, 4096, 320, 'Intel Graphics X4500M / 256MB', 100720, 14, 8, 0),
(31, 'MSI', 'CR700X-023HU', 17.3, 3072, 320, 'NVIDIA GeForce Go 8200M 128MB', 108400, 14, 1, 0),
(32, 'DELL', 'Vostro V860-111696', 15.6, 1024, 250, 'Intel Graphics x3100', 79920, 17, 2, 3),
(33, 'HP', 'Mini 1199 NS528EA', 10.1, 1024, 80, 'Intel Graphics 950', 114000, 18, 12, 3),
(34, 'Asus', 'EEE PC 1001HA-BLK012X BLACK', 10.0, 1024, 160, 'Intel Graphics 4500MHD', 59920, 19, 12, 4),
(35, 'Asus', 'EEE PC 1001HA-WHI009X XP WHITE', 10.0, 1024, 160, 'Intel Graphics 4500MHD', 59920, 19, 12, 4),
(36, 'DELL', 'Inspiron 1011 104442 BLUE', 10.1, 1024, 160, 'Intel Graphics 500', 55920, 19, 2, 3),
(37, 'DELL', 'Inspiron 1011 104437 BLUE', 10.1, 1024, 160, 'Intel Graphics 500', 63992, 19, 12, 1),
(38, 'DELL', 'Inspiron 1011 104435 BLACK', 10.1, 1024, 160, 'Intel Graphics 500', 63992, 19, 12, 4),
(39, 'DELL', 'Inspiron 1011 105566 RED', 10.1, 1024, 160, 'Intel Graphics 500', 63992, 19, 12, 1),
(40, 'DELL', 'Inspiron 1011 104434 WHITE', 10.1, 1024, 160, 'Intel Graphics 500', 63992, 19, 12, 5),
(41, 'DELL', 'Inspiron 1011 104436 PINK', 10.1, 1024, 160, 'Intel Graphics 500', 63992, 19, 12, 0),
(42, 'DELL', 'Inspiron 1011 110960 GREEN', 10.1, 1024, 160, 'Intel Graphics 500', 63992, 19, 12, 5),
(43, 'DELL', 'Inspiron 1011 106751 BLACK', 10.1, 1024, 160, 'Intel Graphics 500', 87920, 19, 12, 3),
(44, 'ACER', 'ASPIRE ONE A150-A BLUE', 8.9, 1024, 120, 'Intel Graphics 950', 58320, 19, 2, 1),
(45, 'ACER', 'ASPIRE ONE D250-0Bw', 10.1, 1024, 160, 'Intel Graphics 950', 68720, 19, 12, 5),
(46, 'ACER', 'ASPIRE ONE D250-0Br', 10.1, 1024, 160, 'Intel Graphics 950', 68720, 19, 12, 3),
(47, 'MSI', 'WIND U100-1033HU', 10.0, 1024, 160, 'Intel Graphics 950', 71920, 19, 12, 2),
(48, 'HP', 'Mini 110c-1010SH NW642EA', 10.1, 1024, 160, 'Intel Graphics 950', 78320, 19, 12, 2),
(49, 'Asus', 'Eee PC 1005HA-WHI059X XP WHITE', 10.0, 1024, 160, 'Intel Graphics 950', 78320, 19, 12, 3),
(50, 'HP', 'Mini 731 NG660EA', 10.1, 1024, 80, 'Intel Graphics 950', 78320, 19, 12, 3),
(51, 'Asus', 'Eee PC 1005HA-BLK076X XP', 10.0, 1024, 160, 'Intel Graphics 950', 78400, 19, 12, 3),
(52, 'LENOVO', 'IdeaPad S10e NS9RLHL R', 10.1, 1024, 160, 'Intel Graphics 950', 79920, 19, 12, 3),
(53, 'LENOVO', 'IdeaPad S10e NS9RJHL', 10.1, 1024, 160, 'Intel Graphics 950', 79920, 19, 12, 5),
(54, 'Asus', 'Eee PC 1002HA-BLK022X XP B', 10.0, 1024, 160, 'Intel Graphics 950', 91999, 19, 12, 5),
(55, 'Asus', 'Eee PC 1004DN-BLK003X GR', 10.1, 1024, 120, 'Intel Graphics 4500MHD', 106700, 20, 12, 4),
(56, 'ACER', 'ASPIRE ONE D250-1Bw', 10.1, 1024, 160, 'Intel Graphics 950', 71120, 20, 12, 5),
(57, 'ACER', 'ASPIRE ONE D250-1B Blue', 10.1, 1024, 160, 'Intel Graphics 950', 71120, 20, 12, 3),
(58, 'MSI', 'WIND U123-013HU BLUE', 10.0, 1024, 160, 'Intel Graphics 950', 72400, 20, 12, 5),
(59, 'MSI', 'WIND U123-012HU RED', 10.0, 1024, 160, 'Intel Graphics 950', 72400, 20, 12, 1),
(60, 'LENOVO', 'IdeaPad S10-2 59-027093 POP ART', 10.1, 1024, 160, 'Intel Graphics 950', 73520, 20, 12, 3),
(61, 'LENOVO', 'IdeaPad S10-2 59-027094 FLOWER SEA', 10.1, 1024, 160, 'Intel Graphics 950', 73520, 20, 12, 5),
(62, 'LENOVO', 'IdeaPad S10-2 59-027108 SAILING', 10.1, 1024, 160, 'Intel Graphics 950', 73520, 20, 12, 0),
(63, 'MSI', 'WIND U123-014HU WHITE', 10.0, 1024, 160, 'Intel Graphics 950', 75600, 20, 12, 3),
(64, 'MSI', 'WIND U123-018HU GRAY', 10.0, 1024, 160, 'Intel Graphics 950', 75600, 20, 12, 4),
(65, 'LENOVO', 'IdeaPad S10-2 59-027036 WHITE', 10.1, 1024, 160, 'Intel Graphics 950', 77520, 20, 12, 3),
(66, 'Asus', 'Eee PC 1005HA-WHI058X XP W', 10.0, 1024, 160, 'Intel Graphics 950', 82320, 20, 12, 2),
(67, 'Asus', 'Eee PC 1005HA-BLK075X XP B', 10.0, 1024, 160, 'Intel Graphics 950', 82400, 20, 12, 3),
(68, 'Asus', 'Eee S101H-BRN073X XP BR', 10.0, 1024, 160, 'Intel Graphics 950', 87120, 20, 12, 4),
(69, 'Asus', 'Eee PC 1008HA-PIK012X XP P', 10.0, 1024, 160, 'Intel Graphics 950', 95920, 20, 12, 5),
(70, 'Asus', 'Eee PC 1008HA-RED008X XP R', 10.0, 1024, 160, 'Intel Graphics 950', 95920, 20, 12, 1),
(71, 'Asus', 'Eee PC 1008HA-BLU021X XP BL', 10.0, 1024, 160, 'Intel Graphics 950', 95920, 20, 12, 0),
(72, 'Asus', 'Eee PC 1008HA-WHI024X XP', 10.0, 1024, 160, 'Intel Graphics 950', 95920, 20, 12, 3),
(73, 'Asus', 'Eee PC 1008HA-BLU036X XP BL', 10.0, 1024, 160, 'Intel Graphics 950', 95920, 20, 12, 5),
(74, 'TOSHIBA', 'NB200-136', 10.1, 1024, 160, 'Intel GMA 950 / 256MB', 95920, 20, 11, 5),
(75, 'Asus', 'Eee PC 1101HA-BLK041X B', 11.6, 1024, 160, 'Intel Graphics 500', 96720, 21, 12, 4),
(76, 'Asus', 'Eee PC 1101HA-BLK028M B', 11.6, 2048, 250, 'Intel Graphics 500', 98000, 21, 11, 5),
(77, 'ACER', 'ASPIRE ONE 751h 52Bb BLACK', 11.6, 1024, 160, 'Intel Graphics 950', 81200, 21, 12, 2),
(78, 'ACER', 'ASPIRE ONE 751h 52Bb WHITE', 11.6, 1024, 160, 'Intel Graphics 950', 81200, 21, 12, 4),
(79, 'ACER', 'ASPIRE ONE 751h 52Bb RED', 11.6, 1024, 160, 'Intel Graphics 950', 81200, 21, 12, 5),
(80, 'ACER', 'ASPIRE ONE 751H PINK', 11.6, 1024, 160, 'Intel Graphics 950', 81200, 21, 12, 3),
(81, 'ACER', 'ASPIRE ONE 751h 52Bb BLUE', 11.6, 1024, 160, 'Intel Graphics 950', 81200, 21, 12, 3),
(82, 'Asus', 'Eee PC 1101HA-BLU018X BLUE', 11.6, 1024, 160, 'Intel Graphics 950', 96720, 21, 12, 1),
(83, 'Asus', 'Eee PC 1101HA-WHI040X W', 11.6, 1024, 160, 'Intel Graphics 950', 96720, 21, 12, 0),
(84, 'Asus', 'Eee PC 1101HA-WHI022M W', 11.6, 2048, 250, 'Intel Graphics 950', 98000, 21, 11, 4),
(85, 'DELL', 'Inspiron 1010 106752 BLACK', 10.1, 1024, 160, 'Intel Graphics 500', 87920, 22, 12, 0),
(86, 'ASUS', 'M51VR-AP184C', 15.4, 2048, 250, 'ATi Mobility Radeon HD3470 256MB', 140720, 23, 6, 4),
(87, 'FUJITSU', 'Esprimo V6535-104060', 15.4, 2048, 250, 'Intel Graphics 4500MHD', 110320, 23, 8, 5),
(88, 'ACER', 'Extensa 5630G-732G16N', 15.4, 2048, 160, 'NVIDIA GeForce Go 9300M 256MB', 127920, 24, 6, 0),
(89, 'DELL', 'Studio XPS 13-711 BLACK', 13.3, 4096, 320, 'NVIDIA GeForce Go 9500M-GS 256MB', 241520, 24, 6, 0),
(90, 'MSI', 'GX723X-271HU', 17.0, 4096, 500, 'NVIDIA GeForce GT130M 512B DDR3', 216720, 24, 1, 1),
(91, 'TOSHIBA', 'Satellite A300-1GN', 15.4, 3072, 320, 'ATi Mobility Radeon HD3650 512MB', 226800, 25, 6, 0),
(92, 'LENOVO', 'ThinkPad T500 NL34EHV', 15.4, 2048, 160, 'Intel Graphics 4500MHD', 241520, 25, 3, 1),
(93, 'LENOVO', 'ThinkPad T400 NM81UHV', 14.1, 2048, 160, 'Intel Graphics 4500MHD', 244720, 25, 3, 5),
(94, 'FUJITSU', 'Lifebook E8420', 15.4, 4096, 160, 'Intel Graphics 4500MHD', 268720, 25, 3, 5),
(95, 'FUJITSU', 'Lifebook S7220', 14.1, 4096, 320, 'Intel Graphics 4500MHD', 268720, 25, 3, 1),
(96, 'FUJITSU', 'Lifebook S6420', 13.3, 4096, 160, 'Intel Graphics 4500MHD', 279920, 25, 3, 3),
(97, 'LENOVO', 'ThinkPad T500 NL346HV', 15.4, 2048, 320, 'Intel Graphics 4500MHD', 279920, 25, 3, 3),
(98, 'LENOVO', 'ThinkPad T500 NJ253HV', 15.4, 2048, 160, 'ATi Mobility Radeon HD3650', 279920, 26, 3, 3),
(99, 'DELL', 'Studio XPS 16-713 BLACK', 16.0, 4096, 500, 'ATi Mobility Radeon HD3670 512MB', 266320, 26, 6, 5),
(100, 'DELL', 'Inspiron 1545-106226 Red', 15.6, 2048, 320, 'ATi Mobility Radeon HD4330 256MB', 169200, 26, 6, 0),
(101, 'DELL', 'Inspiron 1545-106227 Blue', 15.6, 2048, 320, 'ATi Mobility Radeon HD4330 256MB', 169200, 26, 6, 5),
(102, 'DELL', 'Studio 1555-110573 RED', 15.6, 2048, 500, 'ATi Mobility Radeon HD4570 512MB', 192720, 26, 6, 2),
(103, 'DELL', 'Studio 1555-110574 BLACK', 15.6, 2048, 500, 'ATi Mobility Radeon HD4570 512MB', 192720, 26, 6, 1),
(104, 'DELL', 'Studio 1555-110575 BLUE', 15.6, 2048, 500, 'ATi Mobility Radeon HD4570 512MB', 192720, 26, 6, 3),
(105, 'TOSHIBA', 'Satellite P300-225', 17.1, 4096, 500, 'ATi Mobility Radeon HD4650 1024MB', 234800, 26, 6, 3),
(106, 'DELL', 'Studio XPS M1640-106257 B', 15.6, 4096, 500, 'ATi Mobility Radeon HD4670 512MB', 268720, 26, 6, 2),
(107, 'DELL', 'Studio XPS M1640-106259 R', 15.6, 4096, 500, 'ATi Mobility Radeon HD4670 512MB', 268720, 26, 6, 5),
(108, 'LENOVO', 'ThinkPad T500 NJ42RHV', 15.4, 2048, 160, 'Intel Graphics 4500MHD', 255920, 26, 3, 1),
(109, 'FUJITSU', 'Lifebook S7220-1', 14.1, 4096, 320, 'Intel Graphics 4500MHD', 279920, 26, 3, 3),
(110, 'TOSHIBA', 'Tecra M10-14Z', 14.1, 3072, 250, 'NVIDIA Quadro NVS 150M 256MB', 271920, 26, 3, 3),
(111, 'DELL', 'Studio XPS M1340-106255 B', 13.3, 4096, 500, 'NVIDIA GeForce Go 9400M-GS 256MB', 251920, 26, 6, 5),
(112, 'DELL', 'Studio XPS M1340-106256 R', 13.3, 4096, 500, 'NVIDIA GeForce Go 9400M-GS 256MB', 251920, 26, 6, 4),
(113, 'ASUS', 'N80VN-GP023C', 14.1, 4096, 320, 'NVIDIA GeForce 9650M GT 1GB', 215920, 26, 6, 4),
(114, 'ASUS', 'U50VG-XX162V', 15.6, 4096, 500, 'NVIDIA GeForce G105/512MB', 219120, 27, 10, 0),
(115, 'TOSHIBA', 'Qosmio X300-14V', 17.0, 4096, 320, 'NVIDIA GeForce Go 9700M-GT 512MB', 399920, 27, 6, 4),
(116, 'ASUS', 'N71VG-TY046V', 17.3, 4096, 640, 'NVIDIA GeForce GT220M 1GB', 243920, 27, 10, 2),
(117, 'ASUS', 'N61VN-JX069V', 16.0, 4096, 500, 'NVIDIA GeForce GT240M 1GB', 247920, 27, 10, 4),
(118, 'MSI', 'GT628X-447HU', 15.4, 4096, 500, 'NVIDIA GeForce GTS 160M', 258000, 27, 1, 3),
(119, 'HP', 'EliteBook 2530p FU431EA', 12.1, 2048, 120, 'Intel Graphics 4500MHD', 379920, 28, 3, 0),
(120, 'ThinkPad', 'X200 NRRFWHV', 12.1, 2048, 250, 'Intel Graphics 4500MHD', 387120, 28, 3, 2),
(121, 'ACER', 'Timeline 3810TG-734G50N', 13.3, 4096, 500, 'ATi Mobility Radeon HD4330 256MB', 174320, 29, 6, 5),
(122, 'ACER', 'Aspire Timeline 4810TG-733G25MN', 14.0, 3072, 250, 'ATi Mobility Radeon HD4330 512MB', 164720, 29, 10, 3),
(123, 'ACER', 'TravelMate 8471-733G25MN', 14.0, 3072, 250, 'Intel Graphics 4500MHD', 167920, 29, 3, 2),
(124, 'ASUS', 'UL20A-2X022V', 12.1, 3072, 320, 'Intel Graphics X4500M / 256MB', 146800, 29, 10, 3),
(125, 'ASUS', 'UL30A-QX164V', 13.3, 3072, 320, 'Intel Graphics X4500M / 256MB', 148720, 29, 10, 3),
(126, 'ASUS', 'UL50AG-XX007V', 15.6, 4096, 500, 'Intel Graphics X4500M / 256MB', 174320, 29, 10, 3),
(127, 'ASUS', 'UX30-QX096V', 13.3, 3072, 320, 'Intel Graphics X4500M / 256MB', 177520, 29, 10, 1),
(128, 'ASUS', 'UX30-QX085V', 13.3, 4096, 500, 'Intel Graphics X4500M / 256MB', 184720, 29, 10, 0),
(129, 'ASUS', 'UL80AG-WX011V', 14.0, 3072, 320, 'Intel GMA 950 / 256MB', 162320, 29, 10, 5),
(130, 'ASUS', 'UX50V-XX042V', 15.6, 4096, 500, 'NVIDIA GeForce G105/512MB', 203920, 29, 10, 2),
(131, 'ASUS', 'UL50VT-XX021V', 15.6, 4096, 500, 'NVIDIA GeForce GT210M 512GB', 191120, 29, 10, 2),
(132, 'TOSHIBA', 'Portégé A600-139', 12.1, 2048, 250, 'Intel Graphics 4500MHD', 271920, 30, 3, 5),
(133, 'ACER', 'Timeline 3810TG-944G50N', 13.3, 4096, 500, 'ATi Mobility Radeon HD4330 256MB', 194800, 31, 6, 0),
(134, 'ACER', 'Timeline 3810T-944G32N', 13.3, 4096, 320, 'Intel Graphics 4500MHD', 168720, 31, 6, 2),
(135, 'ACER', 'Aspire Timeline 4810T-943G32MN', 14.0, 3072, 320, 'Intel Graphics 4500MHD', 189200, 31, 6, 3),
(136, 'ThinkPad', 'X301 NRFC1HV', 13.3, 2048, 120, 'Intel Graphics 4500MHD', 366000, 31, 3, 0),
(137, 'FUJITSU', 'Esprimo V6515-104062', 15.4, 2048, 250, 'NVIDIA GeForce Go 8200M 128MB', 123920, 32, 8, 1),
(138, 'FUJITSU', 'Esprimo V5535 02', 15.4, 2048, 160, 'SiS Mirage 3+ 256M', 103920, 34, 1, 2),
(139, 'HP', 'ProBook 4510s NX621EA', 15.6, 3072, 320, 'ATi Mobility Radeon HD4330 256MB', 146320, 34, 1, 0),
(140, 'HP', 'ProBook 4510s NX624EA', 15.6, 3072, 320, 'ATi Mobility Radeon HD4330 256MB', 157520, 34, 4, 1),
(141, 'HP', 'ProBook 4710s NX628EA', 17.3, 3072, 320, 'ATi Mobility Radeon HD4330 512MB', 159920, 34, 1, 4),
(142, 'HP', 'COMPAQ 610 NX549EA', 15.6, 1024, 160, 'Intel Graphics x3100', 104990, 34, 1, 1),
(143, 'HP', 'COMPAQ 610 NX550EA', 15.6, 2048, 320, 'Intel Graphics x3100', 121520, 34, 1, 3),
(144, 'HP', 'COMPAQ 610 NX552EA', 15.6, 2048, 320, 'Intel Graphics x3100', 125200, 34, 4, 0),
(145, 'DELL', 'Vostro A860-111877', 15.6, 2048, 250, 'Intel Graphics x3100 ', 94320, 34, 2, 0),
(146, 'FUJITSU', 'Esprimo V6555 MPWE5HU', 15.4, 2048, 250, 'NVIDIA GeForce Go 8200M 128MB', 108000, 34, 2, 2),
(147, 'MSI', 'VX600X-053HU', 15.4, 4096, 500, 'ATi Mobility Radeon HD3410 256MB', 136400, 35, 1, 0),
(148, 'FUJITSU', 'Esprimo V6545-104064', 15.4, 2048, 250, 'ATi Mobility Radeon HD3450 256MB', 143920, 35, 2, 4),
(149, 'FUJITSU', 'Amilo PI 3525', 15.4, 2048, 320, 'Intel Graphics 4500MHD', 111111, 35, 8, 3),
(150, 'FUJITSU', 'Esprimo V6505-104063', 15.4, 2048, 250, 'Intel Graphics 4500MHD ', 135920, 35, 2, 0),
(151, 'MSI', 'CX600X-042HU', 16.0, 4096, 500, 'ATi Mobility Radeon HD4330 256MB', 149600, 36, 8, 1),
(152, 'DELL', 'Inspiron 1545-699 BLUE', 15.6, 4096, 320, 'ATi Mobility Radeon HD4330 256MB', 159920, 36, 6, 2),
(153, 'DELL', 'Studio 1555-635 RED', 15.6, 4096, 500, 'ATi Mobility Radeon HD4570 512MB', 176720, 36, 1, 5),
(154, 'DELL', 'Studio 1555-106249 BLUE', 15.6, 4096, 500, 'ATi Mobility Radeon HD4570 512MB', 190320, 36, 6, 3),
(155, 'ASUS', 'F6A-3P193X', 13.3, 3072, 250, 'Intel Graphics X4500M / 256MB', 159920, 36, 8, 2),
(156, 'ASUS', 'K50IN-SX024L', 15.6, 4096, 250, 'NVIDIA GeForce G102M/512MB', 135920, 36, 8, 1),
(157, 'DELL', 'Studio XPS M1340-110934 B', 13.3, 2048, 320, 'NVIDIA GeForce Go 9400M-GS 256MB', 201520, 36, 6, 5),
(158, 'HP', 'ProBook 4510s VC191EA', 15.6, 3072, 500, 'ATi Mobility Radeon HD4330 256MB', 187600, 37, 6, 5),
(159, 'HP', 'ProBook 4510s NA921EA', 15.6, 2048, 250, 'Intel Graphics 4500MHD', 203920, 37, 3, 2),
(160, 'DELL', 'Inspiron 1545-111827 Red', 15.6, 4096, 320, 'ATi Mobility Radeon HD4330 512MB', 139120, 38, 2, 2),
(161, 'DELL', 'Inspiron 1545-111826 Black', 15.6, 4096, 320, 'ATi Mobility Radeon HD4330 512MB', 139120, 38, 2, 0),
(162, 'DELL', 'Inspiron 1545-111828 Blue', 15.6, 4096, 320, 'ATi Mobility Radeon HD4330 512MB', 139120, 38, 2, 5),
(163, 'DELL', 'Inspiron 1545-111829 White', 15.6, 4096, 320, 'ATi Mobility Radeon HD4330 512MB', 139120, 38, 2, 0),
(164, 'DELL', 'Inspiron 1545-111831 Purple', 15.6, 4096, 320, 'ATi Mobility Radeon HD4330 512MB', 139120, 38, 2, 0),
(165, 'MSI', 'EX627X-400HU', 16.0, 4096, 500, 'ATi Mobility Radeon HD4570 512MB', 164720, 38, 1, 5),
(166, 'ASUS', 'U80V-WX101V', 14.0, 4096, 500, 'ATi Mobility Radeon HD4570 512MB', 199120, 38, 10, 3),
(167, 'LENOVO', 'IdeaPad G550A 59-026421', 15.6, 3072, 320, 'Intel Graphics 4500MHD', 135920, 38, 1, 5),
(168, 'ACER', 'Aspire 5738-663G32MN Linux', 15.6, 3072, 320, 'Intel Graphics 4500MHD ', 123920, 38, 2, 2),
(169, 'ASUS', 'K50IJ-SX152L', 15.6, 4096, 320, 'Intel Graphics X4500M / 256MB', 119920, 38, 8, 0),
(170, 'ASUS', 'K50IN-SX155L', 15.6, 3072, 250, 'NVIDIA GeForce G102M/512MB', 126320, 38, 2, 4),
(171, 'ASUS', 'K50IN-SX157L', 15.6, 4096, 500, 'NVIDIA GeForce G102M/512MB', 131920, 38, 2, 2),
(172, 'ASUS', 'U50VG-XX156V', 15.6, 4096, 500, 'NVIDIA GeForce G105/512MB', 195120, 38, 10, 1),
(173, 'MSI', 'EX723X-079HU', 17.0, 4096, 500, 'NVIDIA GeForce Go 9300M 256MB', 173520, 38, 1, 0),
(174, 'TOSHIBA', 'Satellite U500-17E', 13.3, 2048, 320, 'NVIDIA GeForce GT210M 512GB', 166320, 38, 10, 2),
(175, 'ASUS', 'F50SF-JX061X', 16.0, 4096, 500, 'NVIDIA GeForce GT220M 1GB', 167680, 38, 8, 2),
(176, 'ASUS', 'N61VG-JX070V', 16.0, 4096, 500, 'NVIDIA GeForce GT220M 1GB', 207920, 38, 10, 3),
(177, 'TOSHIBA', 'Satellite A500-1DN', 16.0, 4096, 320, 'NVIDIA GeForce GT230M 1GB', 185520, 38, 10, 2),
(178, 'LENOVO', 'SL500 NRJEBHV', 15.4, 2048, 320, 'Intel Graphics 4500MHD', 169520, 39, 4, 3),
(179, 'FUJITSU', 'Esprimo V5505 02', 15.4, 2048, 250, 'Intel Graphics x3100', 135555, 40, 4, 4),
(180, 'TOSHIBA', 'Satellite A200-23W', 15.4, 2048, 400, 'ATi Mobility Radeon HD2600 512MB', 175920, 41, 6, 0),
(181, 'FUJITSU', 'Esprimo D9500-101571', 15.4, 2048, 160, 'Intel Graphics x3100', 155920, 42, 3, 2),
(182, 'FUJITSU', 'Esprimo D9500-101570', 15.4, 4096, 160, 'Intel Graphics x3100', 179120, 43, 3, 3),
(183, 'Lenovo', 'ThinkPad W500 NRA3KHV', 15.4, 4096, 200, 'Intel Graphics 4500MHD', 380720, 44, 3, 0),
(184, 'ACER', 'Timeline 3810T-352G25N', 13.3, 2048, 250, 'Intel Graphics 4500MHD', 130320, 45, 6, 1),
(185, 'MSI', 'X400-048HU', 14.0, 2048, 500, 'Intel Graphics 4500MHD', 143920, 45, 6, 4),
(186, 'ASUS', 'UX30-QX032C', 13.3, 3072, 500, 'Intel Graphics X4500M / 256MB', 198800, 45, 6, 5),
(187, 'ASUS', 'U20A-2P027C', 12.1, 4096, 500, 'Intel Graphics X4500M / 256MB', 207920, 45, 6, 0),
(188, 'ASUS', 'UX50V-XX007C', 15.6, 4096, 500, 'NVIDIA GeForce G105/512MB', 244720, 45, 6, 2),
(189, 'ACER', 'Timeline 3810TZ-414G32N', 13.3, 4096, 320, 'Intel Graphics 4500MHD', 138320, 46, 9, 3),
(190, 'ACER', 'Timeline 5810TZ-414G32MN Vista', 15.6, 4096, 320, 'Intel Graphics 4500MHD', 142320, 46, 7, 3),
(191, 'ACER', 'Timeline 5810TZ-414G32MN Win7', 15.6, 4096, 320, 'Intel Graphics 4500MHD', 146320, 46, 9, 3),
(192, 'ACER', 'Aspire Timeline 4810TZ-413G25MN', 14.1, 3072, 250, 'Intel Graphics 4500MHD', 150000, 46, 10, 5),
(193, 'TOSHIBA', 'Satellite T130-10G', 13.3, 4096, 320, 'Intel Graphics X4500M / 256MB', 151920, 46, 10, 5),
(194, 'FUJITSU', 'Esprimo V6545', 15.4, 2048, 250, 'ATi Mobility Radeon HD3450 256MB', 110320, 23, 2, 1),
(195, 'TOSHIBA', 'Satellite A300-22Z', 15.4, 2048, 320, 'ATi Mobility Radeon HD3470 256MB', 126000, 23, 8, 5),
(196, 'FUJITSU', 'Esprimo V6505', 15.4, 2048, 250, 'Intel Graphics 4500MHD ', 111111, 23, 2, 2),
(197, 'FUJITSU', 'Amilo PI 3540-104877', 15.4, 3072, 250, 'NVIDIA GeForce Go 9300M 256MB', 115920, 23, 8, 5),
(198, 'MSI', 'VX600X-206HU', 15.4, 4096, 320, 'ATi Mobility Radeon HD3410 256MB', 121520, 48, 1, 4),
(199, 'TOSHIBA', 'Satellite A300-29K', 15.4, 2048, 320, 'ATi Mobility Radeon HD3470 256MB', 125520, 48, 8, 3),
(200, 'TOSHIBA', 'Satellite A300-22W', 15.4, 3072, 320, 'ATi Mobility Radeon HD3470 256MB', 131920, 48, 6, 5),
(201, 'TOSHIBA', 'Satellite A300-29J', 15.4, 4096, 320, 'ATi Mobility Radeon HD3470 256MB', 135120, 48, 6, 3),
(202, 'MSI', 'CX600X-018HU', 16.0, 4096, 320, 'ATi Mobility Radeon HD4330 256MB', 114800, 48, 8, 0),
(203, 'MSI', 'CX700X-013HU', 17.3, 4096, 320, 'ATi Mobility Radeon HD4330 256MB', 133520, 48, 8, 1),
(204, 'HP', 'Pavilion DV6-1120EH NM629EA', 15.6, 3072, 250, 'ATi Mobility Radeon HD4530 512MB', 183992, 48, 6, 3),
(205, 'ASUS', 'F83SE-VX039', 14.0, 4096, 500, 'ATi Mobility Radeon HD4570 512MB', 138320, 48, 8, 5),
(206, 'TOSHIBA', 'Satellite L300-2CE', 15.4, 2048, 250, 'Intel Graphics 4500MHD', 103600, 48, 8, 1),
(207, 'FUJITSU', 'Esprimo V6535-104061', 15.4, 4096, 320, 'Intel Graphics 4500MHD', 118320, 48, 8, 3),
(208, 'FUJITSU', 'Amilo Li 3910-UW5HU', 18.4, 4096, 320, 'Intel Graphics 4500MHD', 123920, 48, 8, 3),
(209, 'ASUS', 'K50IJ-SX025L', 15.6, 4096, 320, 'Intel Graphics 4500MHD', 125520, 48, 8, 3),
(210, 'HP', 'Presario CQ61-110eh NT353EA', 15.6, 2048, 250, 'Intel Graphics 4500MHD', 131920, 48, 4, 4),
(211, 'HP', 'ProBook 4510s VC179ES', 15.6, 3072, 320, 'Intel Graphics 4500MHD', 134320, 48, 1, 3),
(212, 'ASUS', 'F6A-3P154X', 13.3, 3072, 250, 'Intel Graphics X4500M / 256MB', 143120, 48, 8, 4),
(213, 'ASUS', 'K50IN-SX011L', 15.6, 4096, 320, 'NVIDIA GeForce G102M/512MB', 129520, 48, 8, 5),
(214, 'HP', 'Presario CQ61-120eh NL930EA', 15.6, 3072, 250, 'NVIDIA GeForce G103/512MB', 148720, 48, 4, 0),
(215, 'ACER', 'Aspire 5738ZG-422G25MN', 15.6, 2048, 250, 'NVIDIA GeForce G105/512MB', 123120, 48, 4, 4),
(216, 'MSI', 'EX720X-058HU', 17.0, 4096, 500, 'NVIDIA GeForce Go 9300M 256MB', 150320, 48, 1, 0),
(217, 'MSI', 'CX600X-072HU', 16.0, 4096, 500, 'ATi Mobility Radeon HD4330 256MB', 119120, 49, 8, 4),
(218, 'DELL', 'Inspiron 1545-110961 Red', 15.6, 2048, 320, 'ATi Mobility Radeon HD4330 512MB', 134320, 49, 6, 3),
(219, 'DELL', 'Inspiron 1545-110963 Blue', 15.6, 2048, 320, 'ATi Mobility Radeon HD4330 512MB', 134320, 49, 6, 0),
(220, 'DELL', 'Inspiron 1545-110964 White', 15.6, 2048, 320, 'ATi Mobility Radeon HD4330 512MB', 134320, 49, 6, 4),
(221, 'DELL', 'Inspiron 1545-110962 Black', 15.6, 2048, 320, 'ATi Mobility Radeon HD4330 512MB', 134320, 49, 6, 3),
(222, 'ASUS', 'F83SE-VX057D', 14.0, 4096, 500, 'ATi Mobility Radeon HD4570 512MB', 124720, 49, 8, 2),
(223, 'ACER', 'Aspire 5738ZG-432G25MN', 15.6, 2048, 250, 'ATi Mobility Radeon HD4570 512MB', 126320, 49, 5, 5),
(224, 'LENOVO', 'IdeaPad G550L 59-026359', 15.6, 3072, 320, 'Intel Graphics 4500MHD', 103920, 49, 1, 0),
(225, 'TOSHIBA', 'Satellite L300-2C5', 15.4, 2048, 250, 'Intel Graphics 4500MHD', 110320, 49, 6, 3),
(226, 'ACER', 'Aspire 5738Z-434G32MN', 15.6, 4096, 320, 'Intel Graphics 4500MHD', 126320, 49, 6, 3),
(227, 'ACER', 'Extensa 5635Z-431G16MN', 15.6, 1024, 160, 'Intel Graphics 4500MHD ', 94320, 49, 2, 1),
(228, 'TOSHIBA', 'Satellite L500-1EQ', 15.6, 2048, 320, 'Intel Graphics X4500M / 256MB', 103920, 49, 1, 1),
(229, 'ASUS', 'K50IJ-SX148L', 15.6, 2048, 250, 'Intel Graphics X4500M / 256MB', 103920, 49, 8, 1),
(230, 'TOSHIBA', 'Satellite L500-1GE', 15.6, 4096, 320, 'Intel Graphics X4500M / 256MB', 103920, 49, 1, 4),
(231, 'ASUS', 'K50IJ-SX151L', 15.6, 3072, 250, 'Intel Graphics X4500M / 256MB', 110320, 49, 8, 5),
(232, 'ASUS', 'K50IJ-SX151V', 15.6, 3072, 250, 'Intel Graphics X4500M / 256MB', 119920, 49, 9, 0),
(233, 'ASUS', 'K50IJ-SX124L', 15.6, 4096, 320, 'Intel Graphics X4500M / 256MB', 120400, 49, 8, 1),
(234, 'ASUS', 'K70IJ-TY042L', 17.3, 4096, 320, 'Intel Graphics X4500M / 256MB', 131920, 49, 8, 1),
(235, 'ASUS', 'K50IN-SX153L', 15.6, 3072, 250, 'NVIDIA GeForce G102M/512MB', 111920, 49, 2, 2),
(236, 'ASUS', 'K50IN-SX154L', 15.6, 4096, 320, 'NVIDIA GeForce G102M/512MB', 115920, 49, 2, 5),
(237, 'ASUS', 'K50IN-SX153V', 15.6, 3072, 250, 'NVIDIA GeForce G102M/512MB', 127920, 49, 9, 4),
(238, 'ASUS', 'K70IO-TY073L', 17.3, 4096, 320, 'NVIDIA GeForce GT120M 1GB', 138320, 49, 8, 2),
(239, 'ASUS', 'K70IO-TY068V', 17.3, 4096, 250, 'NVIDIA GeForce GT120M 1GB', 156720, 49, 9, 0),
(240, 'ASUS', 'K61IC-JX018D', 15.6, 4096, 500, 'NVIDIA GeForce GT220M 1GB', 143920, 49, 8, 1),
(241, 'LENOVO', 'U350 BLACK', 13.3, 2048, 250, 'Intel Graphics 4500MHD', 111920, 51, 4, 0),
(242, 'MSI', 'X340-037HU', 13.4, 2048, 320, 'Intel Graphics 4500MHD', 135920, 51, 6, 5),
(243, 'LENOVO', 'IdeaPad S12 Black', 12.0, 1024, 160, 'VIA S3 Chrome 9', 97520, 52, 12, 4),
(244, 'LENOVO', 'IdeaPad S12 White', 12.0, 1024, 160, 'VIA S3 Chrome 9', 97520, 52, 12, 4),
(245, 'ASUS', 'K51AC-SX037D', 15.6, 2048, 250, 'ATi Mobility Radeon HD3200 256MB', 98320, 53, 8, 1),
(246, 'ASUS', 'K50AB-SX073D', 15.6, 3072, 250, 'ATi Mobility Radeon HD4570 512MB', 107120, 53, 8, 5),
(248, 'Apple', 'MacBook Pro 16', 13.0, 10488, 512, 'Apple Silicon', 249535, 5, 8, 2),
(250, 'Apple', 'MacBook Pro 16', 0.9, 10, 9, 'Integrated', 1, 51, 6, 1),
(251, 'Samsung', 'VivoBook', 1.4, 10, 9, 'Integrated2', 465416, 7, 2, 8),
(252, 'MSI', 'Katana 15', 15.0, 4098, 2048, 'Radeon RX 9600', 568236, 5, 10, 5),
(254, 'MSI', 'Katana 15', 15.0, 2048, 4084, 'Integrated', 123, 1, 2, 10),
(255, 'Lenovo', 'Legion 17', 17.0, 5096, 2048, 'Geforce RTX 3090', 456941, 1, 5, 7);

-- --------------------------------------------------------

--
-- Tábla szerkezet ehhez a táblához `oprendszer`
--

CREATE TABLE `oprendszer` (
  `id` int(11) NOT NULL,
  `nev` varchar(100) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- A tábla adatainak kiíratása `oprendszer`
--

INSERT INTO `oprendszer` (`id`, `nev`) VALUES
(0, 'Win 12'),
(1, 'FreeDOS'),
(2, 'Linux'),
(3, 'Microsoft Vista Business'),
(4, 'Microsoft Vista Home Basic HU'),
(5, 'Microsoft Vista Home Premium'),
(6, 'Microsoft Vista Home Premium HU'),
(7, 'Microsoft Vista Home Premium HU notebook'),
(8, 'nincs'),
(9, 'Windows 7 Home Premium HU 32Bit'),
(10, 'Windows 7 Home Premium HU 64Bit'),
(11, 'Windows 7 Starter Edition HU'),
(12, 'Windows XP Home Magyar');

-- --------------------------------------------------------

--
-- Tábla szerkezet ehhez a táblához `processzor`
--

CREATE TABLE `processzor` (
  `id` int(11) NOT NULL,
  `gyarto` varchar(50) NOT NULL,
  `tipus` varchar(100) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- A tábla adatainak kiíratása `processzor`
--

INSERT INTO `processzor` (`id`, `gyarto`, `tipus`) VALUES
(0, 'AMD', '5900x'),
(1, 'AMD', 'Athlon 64 X2 QL64'),
(4, 'AMD', 'Athlon TM Neo MV-40'),
(5, 'AMD', 'Mobil Sempron SI-40'),
(6, 'AMD', 'Turion64 X2 TL60'),
(7, 'AMD', 'Turion64 X2 TL64'),
(8, 'AMD', 'Turion64 X2 TL62'),
(10, 'Intel', 'Celeron 900'),
(12, 'Intel', 'Celeron Dual-Core T1600'),
(13, 'Intel', 'Celeron Dual-Core T1700'),
(14, 'Intel', 'Celeron Dual-Core T3000'),
(17, 'Intel', 'Celeron M 560'),
(18, 'Intel', 'Centrino Atom 1600'),
(19, 'Intel', 'Centrino Atom N270'),
(20, 'Intel', 'Centrino Atom N280'),
(21, 'Intel', 'Centrino Atom Z520'),
(22, 'Intel', 'Centrino Atom Z530'),
(23, 'Intel', 'Core Duo T3400'),
(24, 'Intel', 'Core2 Duo P7350'),
(25, 'Intel', 'Core2 Duo P8400'),
(26, 'Intel', 'Core2 Duo P8600'),
(27, 'Intel', 'Core2 Duo P8700'),
(28, 'Intel', 'Core2 Duo SL9400'),
(29, 'Intel', 'Core2 Duo SU7300'),
(30, 'Intel', 'Core2 Duo SU9300'),
(31, 'Intel', 'Core2 Duo SU9400'),
(32, 'Intel', 'Core2 Duo T5670'),
(34, 'Intel', 'Core2 Duo T5870'),
(35, 'Intel', 'Core2 Duo T6400'),
(36, 'Intel', 'Core2 Duo T6500'),
(37, 'Intel', 'Core2 Duo T6570'),
(38, 'Intel', 'Core2 Duo T6600'),
(39, 'Intel', 'Core2 Duo T6670'),
(40, 'Intel', 'Core2 Duo T7300'),
(41, 'Intel', 'Core2 Duo T7500'),
(42, 'Intel', 'Core2 Duo T8300'),
(43, 'Intel', 'Core2 Duo T9300'),
(44, 'Intel', 'Core2 Duo T9400'),
(45, 'Intel', 'Core2 Solo SU3500 ULV'),
(46, 'Intel', 'Pentium Dual Core SU4100'),
(48, 'Intel', 'Pentium dual-core T4200'),
(49, 'Intel', 'Pentium dual-core T4300'),
(51, 'Intel', 'Celeron M ULV723'),
(52, 'VIA', 'Via Nano ULV 2250'),
(53, 'AMD', 'Athlon 64 X2 QL65');

-- --------------------------------------------------------

--
-- Tábla szerkezet ehhez a táblához `sessions`
--

CREATE TABLE `sessions` (
  `session_id` varchar(128) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
  `expires` int(11) UNSIGNED NOT NULL,
  `data` mediumtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_hungarian_ci;

--
-- A tábla adatainak kiíratása `sessions`
--

INSERT INTO `sessions` (`session_id`, `expires`, `data`) VALUES
('LJt1iDMJyYso6Opgxxmk1GXkoVIcgLRD', 1763587118, '{\"cookie\":{\"originalMaxAge\":86400000,\"expires\":\"2025-11-19T21:18:35.336Z\",\"httpOnly\":true,\"path\":\"/\"},\"passport\":{\"user\":1}}');

-- --------------------------------------------------------

--
-- Tábla szerkezet ehhez a táblához `users`
--

CREATE TABLE `users` (
  `id` int(11) NOT NULL,
  `username` varchar(191) NOT NULL,
  `first_name` varchar(191) NOT NULL,
  `last_name` varchar(191) NOT NULL,
  `email` varchar(191) NOT NULL,
  `hash` char(128) NOT NULL,
  `role` enum('visitor','user','admin') NOT NULL DEFAULT 'user',
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_hungarian_ci;

--
-- A tábla adatainak kiíratása `users`
--

INSERT INTO `users` (`id`, `username`, `first_name`, `last_name`, `email`, `hash`, `role`, `created_at`) VALUES
(1, 'aaa', 'norbert', 'kovacs', 'valami@valami.hu', 'c70b5dd9ebfb6f51d09d4132b7170c9d20750a7852f00680f65658f0310e810056e6763c34c9a00b0e940076f54495c169fc2302cceb312039271c43469507dc', 'admin', '2025-11-12 09:02:24'),
(6, 'bbb', 'norbert', 'nagy', 'valami2@valami.hu', 'afdb9638e99117fd7477f3d2d578c6a37a6853945c64e88a81cc8734604cd5afd4fea8c82b1159d943bf1bfc68f6bbcfecd04f61cf5271500f125bd4f756c2ba', 'user', '2025-11-12 10:26:35'),
(7, 'ccc', 'norbi', 'nagy', 'valami3@valami.hu', 'ba3253876aed6bc22d4a6ff53d8406c6ad864195ed144ab5c87621b6c233b548baeae6956df346ec8c17f5ea10f35ee3cbc514797ed7ddd3145464e2a0bab413', 'user', '2025-11-13 07:51:26'),
(8, 'norbi', 'norbert', 'kovacs', 'ez@az.hu', 'ba3253876aed6bc22d4a6ff53d8406c6ad864195ed144ab5c87621b6c233b548baeae6956df346ec8c17f5ea10f35ee3cbc514797ed7ddd3145464e2a0bab413', 'user', '2025-11-14 11:26:24');

--
-- Indexek a kiírt táblákhoz
--

--
-- A tábla indexei `contact_messages`
--
ALTER TABLE `contact_messages`
  ADD PRIMARY KEY (`id`),
  ADD KEY `fk_contact_user` (`user_id`);

--
-- A tábla indexei `gep`
--
ALTER TABLE `gep`
  ADD PRIMARY KEY (`id`),
  ADD KEY `fk_gep_cpu` (`processzorid`),
  ADD KEY `fk_gep_os` (`oprendszerid`);

--
-- A tábla indexei `oprendszer`
--
ALTER TABLE `oprendszer`
  ADD PRIMARY KEY (`id`);

--
-- A tábla indexei `processzor`
--
ALTER TABLE `processzor`
  ADD PRIMARY KEY (`id`);

--
-- A tábla indexei `sessions`
--
ALTER TABLE `sessions`
  ADD PRIMARY KEY (`session_id`);

--
-- A tábla indexei `users`
--
ALTER TABLE `users`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `username` (`username`),
  ADD UNIQUE KEY `uq_users_email` (`email`);

--
-- A kiírt táblák AUTO_INCREMENT értéke
--

--
-- AUTO_INCREMENT a táblához `contact_messages`
--
ALTER TABLE `contact_messages`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=17;

--
-- AUTO_INCREMENT a táblához `gep`
--
ALTER TABLE `gep`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=257;

--
-- AUTO_INCREMENT a táblához `users`
--
ALTER TABLE `users`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=9;

--
-- Megkötések a kiírt táblákhoz
--

--
-- Megkötések a táblához `contact_messages`
--
ALTER TABLE `contact_messages`
  ADD CONSTRAINT `fk_contact_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE SET NULL;

--
-- Megkötések a táblához `gep`
--
ALTER TABLE `gep`
  ADD CONSTRAINT `fk_gep_cpu` FOREIGN KEY (`processzorid`) REFERENCES `processzor` (`id`),
  ADD CONSTRAINT `fk_gep_os` FOREIGN KEY (`oprendszerid`) REFERENCES `oprendszer` (`id`);
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;

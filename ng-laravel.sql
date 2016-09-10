-- phpMyAdmin SQL Dump
-- version 4.1.14
-- http://www.phpmyadmin.net
--
-- Host: 127.0.0.1
-- Generation Time: Jun 11, 2016 at 12:32 PM
-- Server version: 5.6.17
-- PHP Version: 5.5.12

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;

--
-- Database: `ng-laravel`
--

-- --------------------------------------------------------

--
-- Table structure for table `categories`
--

CREATE TABLE IF NOT EXISTS `categories` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `name` varchar(50) COLLATE utf8_unicode_ci DEFAULT NULL,
  `description` varchar(255) COLLATE utf8_unicode_ci DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `updated_at` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB  DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci AUTO_INCREMENT=7 ;

--
-- Dumping data for table `categories`
--

INSERT INTO `categories` (`id`, `name`, `description`, `created_at`, `updated_at`) VALUES
(1, 'Bug Fix', 'Issues That related to program', '0000-00-00 00:00:00', '2016-04-09 15:07:09'),
(3, 'UI Design', 'Task that related to UI Design', '0000-00-00 00:00:00', '2016-04-09 15:07:57'),
(4, 'Implement', 'Task that related to code implement', '0000-00-00 00:00:00', '2016-04-09 15:08:23'),
(5, 'Documentation', 'Task that related to doc writing', '0000-00-00 00:00:00', '2016-04-09 15:09:11');

-- --------------------------------------------------------

--
-- Table structure for table `comments`
--

CREATE TABLE IF NOT EXISTS `comments` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `comment_text` varchar(250) COLLATE utf8_unicode_ci DEFAULT NULL,
  `user_id` int(10) unsigned DEFAULT NULL,
  `task_id` int(10) unsigned DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `updated_at` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  PRIMARY KEY (`id`),
  KEY `comments_user_id_foreign` (`user_id`),
  KEY `comments_task_id_foreign` (`task_id`)
) ENGINE=InnoDB  DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci AUTO_INCREMENT=19 ;

--
-- Dumping data for table `comments`
--

INSERT INTO `comments` (`id`, `comment_text`, `user_id`, `task_id`, `created_at`, `updated_at`) VALUES
(1, 'I need to ftp account to upload image', 1, 1, '2016-04-09 15:30:26', '2016-04-09 15:30:26'),
(3, 'I change login page and backup last page...', 1, 3, '2016-04-09 15:42:15', '2016-04-09 15:42:15'),
(4, 'user:  ftp01\npass:  25a4sd4asdasddsf545\nexpire:  2016-06-22', 2, 1, '2016-04-09 15:44:31', '2016-04-09 15:44:31'),
(5, 'I will change', 1, 6, '2016-04-09 17:04:08', '2016-04-09 17:04:08'),
(7, 'It''s excellent :)', 1, 12, '2016-04-09 17:27:01', '2016-04-09 17:27:01'),
(8, 'Lorem ipsum dolor sit amet, consectetuer adipiscing \nelit. Aenean commodo ligula eget dolor. Aenean massa. \nCum sociis natoque penatibus et magnis dis parturient \nmontes, nascetur ridiculus mus. Donec quam felis, \nultricies nec, pellentesque eu, pret', 1, 9, '2016-04-09 17:28:18', '2016-04-09 17:28:18'),
(10, 'Lorem ipsum dolor sit amet, consectetuer adipiscing \nelit. Aenean commodo ligula eget dolor. Aenean massa. \nCum sociis natoque penatibus et magnis dis parturient \nmontes, nascetur ridiculus mus. Donec quam felis, \nultricies nec, pellentesque eu, pret', 1, 8, '2016-04-09 17:28:49', '2016-04-09 17:28:49'),
(11, 'Lorem ipsum dolor sit amet, sed an cibo percipit', 1, 7, '2016-04-09 17:29:46', '2016-04-09 17:29:47'),
(12, 'test@example.com', 2, 10, '2016-04-09 17:30:15', '2016-04-09 17:30:15'),
(13, 'Thanks', 2, 9, '2016-04-09 17:30:33', '2016-04-09 17:30:33'),
(14, 'Comment at least 6 chararcters', 2, 2, '2016-04-09 17:32:09', '2016-04-09 17:32:09'),
(15, 'very nice :)', 2, 3, '2016-04-09 17:32:51', '2016-04-09 17:32:51'),
(17, 'Hello world', 1, 13, '2016-05-23 04:12:19', '2016-05-23 04:12:20'),
(18, 'assssssssss', 1, 1, '2016-06-07 01:21:09', '2016-06-07 01:21:09');

-- --------------------------------------------------------

--
-- Table structure for table `galleries`
--

CREATE TABLE IF NOT EXISTS `galleries` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `filename` varchar(100) COLLATE utf8_unicode_ci DEFAULT NULL,
  `size` int(11) DEFAULT NULL,
  `task_id` int(10) unsigned DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `updated_at` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  PRIMARY KEY (`id`),
  KEY `galleries_task_id_foreign` (`task_id`)
) ENGINE=InnoDB  DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci AUTO_INCREMENT=21 ;

--
-- Dumping data for table `galleries`
--

INSERT INTO `galleries` (`id`, `filename`, `size`, `task_id`, `created_at`, `updated_at`) VALUES
(7, 'QdiVRGC2xMUNkU9XNDmPNExuR.jpg', 97089, 7, '2016-04-09 17:05:19', '2016-04-09 17:05:19'),
(8, 'fChR4p21YrU6urSz3biw0BFtK.jpg', 109091, 9, '2016-04-09 17:14:40', '2016-04-09 17:14:40'),
(11, '41A12FpOnrPqETTfG6UZQGdHJ.jpg', 88554, 1, '2016-04-13 15:21:22', '2016-04-13 15:21:22'),
(12, '47wM0rEFWKoOXZbM4auDmiIcE.jpg', 119045, 1, '2016-04-13 15:21:22', '2016-04-13 15:21:22'),
(13, 'a09PNydOdD5vVJm7zhudt1CjZ.jpg', 99775, 1, '2016-04-13 15:21:22', '2016-04-13 15:21:22'),
(14, 'K3BtfoxDD5oqTC9TiF1w3967N.jpg', 141115, 1, '2016-04-13 15:21:22', '2016-04-13 15:21:22'),
(15, 'rRFownyn2CawLkHKTzNmFLQGK.jpg', 123100, 3, '2016-04-13 15:22:17', '2016-04-13 15:22:17'),
(16, 'OaPd50GoxpvQhXM6V5D3dPL10.jpg', 55222, 4, '2016-04-13 15:22:56', '2016-04-13 15:22:56'),
(17, 'FVQvfuVanbYlXIfM6BiqDWmSB.jpg', 109091, 10, '2016-04-13 15:23:57', '2016-04-13 15:23:57'),
(18, '8kdTaBKun3WzB3AUufClCD8cj.jpg', 87371, 11, '2016-04-13 15:24:43', '2016-04-13 15:24:43'),
(20, 'sCu9eoHIN1IE7rhOTSLU5rxyC.jpg', 71393, 13, '2016-05-23 04:14:15', '2016-05-23 04:14:15');

-- --------------------------------------------------------

--
-- Table structure for table `migrations`
--

CREATE TABLE IF NOT EXISTS `migrations` (
  `migration` varchar(255) COLLATE utf8_unicode_ci NOT NULL,
  `batch` int(11) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;

--
-- Dumping data for table `migrations`
--

INSERT INTO `migrations` (`migration`, `batch`) VALUES
('2014_10_12_000000_create_users_table', 1),
('2014_10_12_100000_create_password_resets_table', 1),
('2015_07_25_145818_entrust_setup_tables', 1),
('2015_08_20_084811_users_add_profiles_field', 1),
('2015_08_30_031807_users_create_table_route_permission', 1),
('2015_09_01_075306_users_add_status_field', 1),
('2015_09_04_021739_users_add_birthday_gender_field', 1),
('2015_12_11_072547_users_add_soft_delete_field', 1),
('2016_03_06_074735_category', 1),
('2016_03_09_100353_task', 1),
('2016_03_10_084500_comment', 1),
('2016_03_10_094256_add_permission', 1),
('2016_03_10_095323_tag', 1),
('2016_03_10_100124_gallery', 1),
('2016_03_15_075106_tasktags', 1),
('2016_05_04_132039_excel_permission', 2);

-- --------------------------------------------------------

--
-- Table structure for table `password_resets`
--

CREATE TABLE IF NOT EXISTS `password_resets` (
  `email` varchar(255) COLLATE utf8_unicode_ci NOT NULL,
  `token` varchar(255) COLLATE utf8_unicode_ci NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  KEY `password_resets_email_index` (`email`),
  KEY `password_resets_token_index` (`token`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `permissions`
--

CREATE TABLE IF NOT EXISTS `permissions` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `name` varchar(255) COLLATE utf8_unicode_ci NOT NULL,
  `display_name` varchar(255) COLLATE utf8_unicode_ci DEFAULT NULL,
  `description` varchar(255) COLLATE utf8_unicode_ci DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `updated_at` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  PRIMARY KEY (`id`),
  UNIQUE KEY `permissions_name_unique` (`name`)
) ENGINE=InnoDB  DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci AUTO_INCREMENT=47 ;

--
-- Dumping data for table `permissions`
--

INSERT INTO `permissions` (`id`, `name`, `display_name`, `description`, `created_at`, `updated_at`) VALUES
(1, 'view_dashboard', 'view_dashboard', NULL, '0000-00-00 00:00:00', '0000-00-00 00:00:00'),
(2, 'view_admin', 'view_admin', NULL, '0000-00-00 00:00:00', '0000-00-00 00:00:00'),
(3, 'add_request', 'add_request', NULL, '0000-00-00 00:00:00', '0000-00-00 00:00:00'),
(4, 'edit_request', 'edit_request', NULL, '0000-00-00 00:00:00', '0000-00-00 00:00:00'),
(5, 'delete_request', 'delete_request', NULL, '0000-00-00 00:00:00', '0000-00-00 00:00:00'),
(6, 'view_request', 'view_request', NULL, '0000-00-00 00:00:00', '0000-00-00 00:00:00'),
(7, 'add_customer', 'add_customer', NULL, '0000-00-00 00:00:00', '0000-00-00 00:00:00'),
(8, 'edit_customer', 'edit_customer', NULL, '0000-00-00 00:00:00', '0000-00-00 00:00:00'),
(9, 'delete_customer', 'delete_customer', NULL, '0000-00-00 00:00:00', '0000-00-00 00:00:00'),
(10, 'view_customer', 'view_customer', NULL, '0000-00-00 00:00:00', '0000-00-00 00:00:00'),
(11, 'add_category', 'add_category', NULL, '0000-00-00 00:00:00', '0000-00-00 00:00:00'),
(12, 'edit_category', 'edit_category', NULL, '0000-00-00 00:00:00', '0000-00-00 00:00:00'),
(13, 'delete_category', 'delete_category', NULL, '0000-00-00 00:00:00', '0000-00-00 00:00:00'),
(14, 'view_category', 'view_category', NULL, '0000-00-00 00:00:00', '0000-00-00 00:00:00'),
(15, 'view_user', 'view_user', NULL, '0000-00-00 00:00:00', '0000-00-00 00:00:00'),
(16, 'add_user', 'add_user', NULL, '0000-00-00 00:00:00', '0000-00-00 00:00:00'),
(17, 'edit_user', 'edit_user', NULL, '0000-00-00 00:00:00', '0000-00-00 00:00:00'),
(18, 'delete_user', 'delete_user', NULL, '0000-00-00 00:00:00', '0000-00-00 00:00:00'),
(19, 'view_role', 'view_role', NULL, '0000-00-00 00:00:00', '0000-00-00 00:00:00'),
(20, 'add_role', 'add_role', NULL, '0000-00-00 00:00:00', '0000-00-00 00:00:00'),
(21, 'edit_role', 'edit_role', NULL, '0000-00-00 00:00:00', '0000-00-00 00:00:00'),
(22, 'delete_role', 'delete_role', NULL, '0000-00-00 00:00:00', '0000-00-00 00:00:00'),
(23, 'view_permission', 'view_permission', NULL, '0000-00-00 00:00:00', '0000-00-00 00:00:00'),
(24, 'add_permission', 'add_permission', NULL, '0000-00-00 00:00:00', '0000-00-00 00:00:00'),
(25, 'edit_permission', 'edit_permission', NULL, '0000-00-00 00:00:00', '0000-00-00 00:00:00'),
(26, 'delete_permission', 'delete_permission', NULL, '0000-00-00 00:00:00', '0000-00-00 00:00:00'),
(27, 'export_csv', 'export_csv', NULL, '0000-00-00 00:00:00', '0000-00-00 00:00:00'),
(28, 'export_xls', 'export_xls', NULL, '0000-00-00 00:00:00', '0000-00-00 00:00:00'),
(29, 'view_news_category', 'view_news_category', NULL, '0000-00-00 00:00:00', '0000-00-00 00:00:00'),
(30, 'add_news_category', 'add_news_category', NULL, '0000-00-00 00:00:00', '0000-00-00 00:00:00'),
(31, 'edit_news_category', 'edit_news_category', NULL, '0000-00-00 00:00:00', '0000-00-00 00:00:00'),
(32, 'delete_news_category', 'delete_news_category', NULL, '0000-00-00 00:00:00', '0000-00-00 00:00:00'),
(33, 'add_gallery', 'add_gallery', NULL, '0000-00-00 00:00:00', '0000-00-00 00:00:00'),
(34, 'edit_gallery', 'edit_gallery', NULL, '0000-00-00 00:00:00', '0000-00-00 00:00:00'),
(35, 'view_gallery', 'view_gallery', NULL, '0000-00-00 00:00:00', '0000-00-00 00:00:00'),
(36, 'delete_gallery', 'delete_gallery', NULL, '0000-00-00 00:00:00', '0000-00-00 00:00:00'),
(37, 'view_task', 'view_task', NULL, '0000-00-00 00:00:00', '0000-00-00 00:00:00'),
(38, 'add_task', 'add_task', NULL, '0000-00-00 00:00:00', '0000-00-00 00:00:00'),
(39, 'delete_task', 'delete_task', NULL, '0000-00-00 00:00:00', '0000-00-00 00:00:00'),
(40, 'edit_task', 'edit_task', NULL, '0000-00-00 00:00:00', '0000-00-00 00:00:00'),
(41, 'view_comment', 'view_comment', NULL, '0000-00-00 00:00:00', '0000-00-00 00:00:00'),
(42, 'add_comment', 'add_comment', NULL, '0000-00-00 00:00:00', '0000-00-00 00:00:00'),
(43, 'edit_comment', 'edit_comment', NULL, '0000-00-00 00:00:00', '0000-00-00 00:00:00'),
(44, 'delete_comment', 'delete_comment', NULL, '0000-00-00 00:00:00', '0000-00-00 00:00:00'),
(45, 'export_pdf', 'export_pdf', NULL, '0000-00-00 00:00:00', '0000-00-00 00:00:00'),
(46, 'import_user', 'import_user', NULL, '0000-00-00 00:00:00', '0000-00-00 00:00:00');

-- --------------------------------------------------------

--
-- Table structure for table `permission_role`
--

CREATE TABLE IF NOT EXISTS `permission_role` (
  `permission_id` int(10) unsigned NOT NULL,
  `role_id` int(10) unsigned NOT NULL,
  PRIMARY KEY (`permission_id`,`role_id`),
  KEY `permission_role_role_id_foreign` (`role_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;

--
-- Dumping data for table `permission_role`
--

INSERT INTO `permission_role` (`permission_id`, `role_id`) VALUES
(1, 1),
(2, 1),
(3, 1),
(4, 1),
(5, 1),
(6, 1),
(7, 1),
(8, 1),
(9, 1),
(10, 1),
(11, 1),
(12, 1),
(13, 1),
(14, 1),
(15, 1),
(16, 1),
(17, 1),
(18, 1),
(19, 1),
(20, 1),
(21, 1),
(22, 1),
(23, 1),
(24, 1),
(25, 1),
(26, 1),
(27, 1),
(28, 1),
(29, 1),
(30, 1),
(31, 1),
(32, 1),
(33, 1),
(34, 1),
(35, 1),
(36, 1),
(37, 1),
(38, 1),
(39, 1),
(40, 1),
(41, 1),
(42, 1),
(43, 1),
(44, 1),
(45, 1),
(46, 1),
(1, 2),
(2, 2),
(6, 2),
(14, 2),
(15, 2),
(19, 2),
(29, 2),
(35, 2),
(37, 2),
(41, 2),
(2, 4),
(11, 4),
(13, 4),
(14, 4);

-- --------------------------------------------------------

--
-- Table structure for table `roles`
--

CREATE TABLE IF NOT EXISTS `roles` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `name` varchar(255) COLLATE utf8_unicode_ci NOT NULL,
  `display_name` varchar(255) COLLATE utf8_unicode_ci DEFAULT NULL,
  `description` varchar(255) COLLATE utf8_unicode_ci DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `updated_at` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  PRIMARY KEY (`id`),
  UNIQUE KEY `roles_name_unique` (`name`)
) ENGINE=InnoDB  DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci AUTO_INCREMENT=5 ;

--
-- Dumping data for table `roles`
--

INSERT INTO `roles` (`id`, `name`, `display_name`, `description`, `created_at`, `updated_at`) VALUES
(1, 'administrators', 'administrators', 'This role is super role and access to all pages', '0000-00-00 00:00:00', '2016-04-09 15:22:03'),
(2, 'viewer_role', 'viewer_role', 'This role just can be view', '2016-04-09 15:24:51', '2016-04-09 15:24:51'),
(3, 'administrator', NULL, NULL, '2016-05-23 04:23:14', '2016-05-23 04:23:14'),
(4, 'guest_role', 'guest_role', NULL, '2016-05-23 04:23:14', '2016-05-23 05:42:35');

-- --------------------------------------------------------

--
-- Table structure for table `role_user`
--

CREATE TABLE IF NOT EXISTS `role_user` (
  `user_id` int(10) unsigned NOT NULL,
  `role_id` int(10) unsigned NOT NULL,
  PRIMARY KEY (`user_id`,`role_id`),
  KEY `role_user_role_id_foreign` (`role_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;

--
-- Dumping data for table `role_user`
--

INSERT INTO `role_user` (`user_id`, `role_id`) VALUES
(1, 1),
(2, 1),
(3, 2),
(4, 3),
(5, 4);

-- --------------------------------------------------------

--
-- Table structure for table `route_permission`
--

CREATE TABLE IF NOT EXISTS `route_permission` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `route` varchar(255) COLLATE utf8_unicode_ci NOT NULL,
  `permissions` varchar(255) COLLATE utf8_unicode_ci DEFAULT NULL,
  `roles` varchar(255) COLLATE utf8_unicode_ci DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `updated_at` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  PRIMARY KEY (`id`),
  UNIQUE KEY `route_permission_route_unique` (`route`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci AUTO_INCREMENT=1 ;

-- --------------------------------------------------------

--
-- Table structure for table `tags`
--

CREATE TABLE IF NOT EXISTS `tags` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `tag` varchar(100) COLLATE utf8_unicode_ci DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `updated_at` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB  DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci AUTO_INCREMENT=8 ;

--
-- Dumping data for table `tags`
--

INSERT INTO `tags` (`id`, `tag`, `created_at`, `updated_at`) VALUES
(1, 'upload', '2016-04-09 15:29:22', '2016-04-09 15:29:22'),
(2, 'website', '2016-04-09 15:29:22', '2016-04-09 15:29:22'),
(3, 'crm', '2016-04-09 15:33:55', '2016-04-09 15:33:55'),
(4, 'bug', '2016-04-09 15:33:55', '2016-04-09 15:33:55'),
(5, 'mobile', '2016-04-09 17:05:19', '2016-04-09 17:05:19'),
(6, 'support', '2016-04-09 17:23:03', '2016-04-09 17:23:03'),
(7, 'newYepTag', '2016-05-23 04:10:43', '2016-05-23 04:10:43');

-- --------------------------------------------------------

--
-- Table structure for table `tasks`
--

CREATE TABLE IF NOT EXISTS `tasks` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `title` varchar(50) COLLATE utf8_unicode_ci DEFAULT NULL,
  `description` varchar(1024) COLLATE utf8_unicode_ci DEFAULT NULL,
  `start_date` date DEFAULT NULL,
  `end_date` date DEFAULT NULL,
  `task_status` tinyint(1) DEFAULT NULL,
  `user_id` int(10) unsigned DEFAULT NULL,
  `category_id` int(10) unsigned DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `updated_at` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  PRIMARY KEY (`id`),
  KEY `tasks_user_id_foreign` (`user_id`),
  KEY `tasks_category_id_foreign` (`category_id`)
) ENGINE=InnoDB  DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci AUTO_INCREMENT=14 ;

--
-- Dumping data for table `tasks`
--

INSERT INTO `tasks` (`id`, `title`, `description`, `start_date`, `end_date`, `task_status`, `user_id`, `category_id`, `created_at`, `updated_at`) VALUES
(1, 'Upload a new catalog in website and new slider', '<p></p><dl>\n   <dt>Definition list</dt>\n   <dd>Consectetur adipisicing elit, sed do eiusmod tempor incididunt ut labore et dolore magna \naliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea \ncommodo consequat.</dd>\n   <dt>Lorem ipsum dolor sit amet</dt>\n   <dd>Consectetur adipisicing elit, sed do eiusmod tempor incididunt ut labore et dolore magna \naliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea \ncommodo consequat.</dd></dl><p></p><p></p><dl><dd><br></dd></dl><p></p><p></p><dl><dd>Thank you</dd>\n</dl><p></p>', '2016-04-12', '2016-04-12', 0, 2, 5, '2016-04-09 15:29:21', '2016-04-13 15:21:22'),
(2, 'I don''t login to CRM program', '<p>Hi</p><p>I have problem with login in CRM. My account is :</p><pre>username: user05<br>password : pas123456</pre><p><br></p><p>Thanks</p>', '2016-04-18', '2016-04-21', 0, 1, 1, '2016-04-09 15:33:55', '2016-04-09 15:33:55'),
(3, 'Change new design of login form', '<p>Hi</p><p>Pellentesque habitant morbi tristique senectus et netus et malesuada fames ac turpis egestas. Vestibulum tortor quam, feugiat vitae, ultricies eget, tempor sit amet, ante. Donec eu libero sit amet quam egestas semper. Aenean ultricies mi vitae est. Mauris placerat eleifend leo. Quisque sit amet est et sapien ullamcorper pharetra. Vestibulum erat wisi, condimentum sed, commodo vitae, ornare sit amet, wisi. Aenean fermentum, elit eget tincidunt condimentum, eros ipsum rutrum orci, sagittis tempus lacus enim ac dui. Donec non enim in turpis pulvinar facilisis. Ut felis. Praesent dapibus, neque id cursus faucibus, tortor neque egestas augue, eu vulputate magna eros eu erat. Aliquam erat volutpat. Nam dui mi, tincidunt quis, accumsan porttitor, facilisis luctus, metus.</p><p><br></p><p>Thanks</p>', '2016-04-12', '2016-04-12', 0, 3, 3, '2016-04-09 15:36:50', '2016-04-13 15:22:16'),
(4, 'change vector presentation keynote', '<h1>HTML Ipsum Presents</h1>\n	       \n<p><strong>Pellentesque habitant morbi tristique</strong> senectus et netus et malesuada fames ac turpis egestas. Vestibulum tortor quam, feugiat vitae, ultricies eget, tempor sit amet, ante. Donec eu libero sit amet quam egestas semper. <em>Aenean ultricies mi vitae est.</em> Mauris placerat eleifend leo. Quisque sit amet est et sapien ullamcorper pharetra. Vestibulum erat wisi, condimentum sed, <code>commodo vitae</code>, ornare sit amet, wisi. Aenean fermentum, elit eget tincidunt condimentum, eros ipsum rutrum orci, sagittis tempus lacus enim ac dui. <a href="#">Donec non enim</a> in turpis pulvinar facilisis. Ut felis.</p>\n\n<h2>Header Level 2</h2>\n	       \n<ol>\n   <li>Lorem ipsum dolor sit amet, consectetuer adipiscing elit.</li>\n   <li>Aliquam tincidunt mauris eu risus.</li>\n</ol>\n\n<blockquote><p>Lorem ipsum dolor sit amet, consectetur adipiscing elit. Vivamus magna. Cras in mi at felis aliquet congue. Ut a est eget ligula molestie gravida. Curabitur massa. Donec el', '2016-04-12', '2016-04-12', 1, 1, 4, '2016-04-09 15:40:33', '2016-04-13 15:22:56'),
(5, 'csdfsd', '<p>sdsdsd</p>', '2016-04-08', '2016-04-08', 0, 2, 3, '2016-04-09 16:10:54', '2016-04-09 16:10:54'),
(6, 'Change product price', '<p>Hi</p><p>Please change price in website</p><table class="table table-bordered"><tbody><tr><td>Title</td><td>Description</td><td>Price</td><td>Tax</td><td>Quantity<br></td></tr><tr><td>MacBook Air</td><td>Lorem ipsum dolor sit amet, consectetuer<br></td><td>850 $</td><td>15%</td><td>22</td></tr><tr><td>iPhone 6</td><td>Lorem ipsum dolor sit amet<br></td><td>655 $</td><td>12%</td><td>15</td></tr><tr><td>iMac 22"</td><td>&nbsp;sit amet, consectetuer&nbsp;Lorem ipsum dolor sit amet<br></td><td>896</td><td>17%</td><td>16</td></tr></tbody></table><p>Thanks</p>', '2016-04-08', '2016-04-08', 0, 2, 4, '2016-04-09 17:02:53', '2016-04-09 17:03:42'),
(7, 'Morbi in sem quis dui placerat', '<p>Pellentesque habitant morbi tristique senectus et netus et malesuada fames ac turpis egestas. Vestibulum tortor quam, feugiat vitae, ultricies eget, tempor sit amet, ante. Donec eu libero sit amet quam egestas semper. Aenean ultricies mi vitae est. Mauris placerat eleifend leo. Quisque sit amet est et sapien ullamcorper pharetra. Vestibulum erat wisi, condimentum sed, commodo vitae, ornare sit amet, wisi. Aenean fermentum, elit eget tincidunt condimentum, eros ipsum rutrum orci, sagittis tempus lacus enim ac dui. Donec non enim in turpis pulvinar facilisis. Ut felis. Praesent dapibus, neque id cursus faucibus, tortor neque egestas augue, eu vulputate magna eros eu erat. Aliquam erat volutpat. Nam dui mi, tincidunt quis, accumsan porttitor, facilisis luctus, metus</p>\n\n<p>Pellentesque habitant morbi tristique senectus et netus et malesuada fames ac turpis egestas. Vestibulum tortor quam, feugiat vitae, ultricies eget, tempor sit amet, ante. Donec eu libero sit amet quam egestas semper. Aenean ultricies mi v', '2016-04-08', '2016-04-08', 1, 3, 3, '2016-04-09 17:05:19', '2016-04-09 17:05:19'),
(8, 'Lorem ipsum dolor sit amet, consectetuer adipiscin', '<p></p><dl>\n   <dt>Definition list</dt>\n   <dd>Consectetur adipisicing elit, sed do eiusmod tempor incididunt ut labore et dolore magna \naliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea \ncommodo consequat.</dd>\n   <dt>Lorem ipsum dolor sit amet</dt>\n   <dd>Consectetur adipisicing elit, sed do eiusmod tempor incididunt ut labore et dolore magna \naliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea \ncommodo consequat.</dd></dl><p></p><p></p><dl><dd><br></dd></dl><p></p>\n<blockquote>\nLorem ipsum dolor sit amet, consectetuer \nadipiscing elit. Aenean commodo ligula eget dolor. \nAenean massa <strong>strong</strong>. Cum sociis \nnatoque penatibus et magnis dis parturient montes, \nnascetur ridiculus mus. Donec quam felis, ultricies \nnec, pellentesque eu, pretium quis, sem. Nulla consequat \nmassa quis enim. Donec pede justo, fringilla vel, \naliquet nec, vulputate eget, arcu. In <em>em</em> \nenim justo, rhoncus ut, imperdiet a, ', '2016-04-30', '2016-05-26', 0, 1, 3, '2016-04-09 17:12:14', '2016-04-09 17:12:14'),
(9, 'Connect to MySql Database and resolve it', '<div>Hi Dear</div><div><img src="data:image/jpeg;base64,/9j/4AAQSkZJRgABAQEASABIAAD/4gxYSUNDX1BST0ZJTEUAAQEAAAxITGlubwIQAABtbnRyUkdCIFhZWiAHzgACAAkABgAxAABhY3NwTVNGVAAAAABJRUMgc1JHQgAAAAAAAAAAAAAAAAAA9tYAAQAAAADTLUhQICAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABFjcHJ0AAABUAAAADNkZXNjAAABhAAAAGx3dHB0AAAB8AAAABRia3B0AAACBAAAABRyWFlaAAACGAAAABRnWFlaAAACLAAAABRiWFlaAAACQAAAABRkbW5kAAACVAAAAHBkbWRkAAACxAAAAIh2dWVkAAADTAAAAIZ2aWV3AAAD1AAAACRsdW1pAAAD+AAAABRtZWFzAAAEDAAAACR0ZWNoAAAEMAAAAAxyVFJDAAAEPAAACAxnVFJDAAAEPAAACAxiVFJDAAAEPAAACAx0ZXh0AAAAAENvcHlyaWdodCAoYykgMTk5OCBIZXdsZXR0LVBhY2thcmQgQ29tcGFueQAAZGVzYwAAAAAAAAASc1JHQiBJRUM2MTk2Ni0yLjEAAAAAAAAAAAAAABJzUkdCIElFQzYxOTY2LTIuMQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWFlaIAAAAAAAAPNRAAEAAAABFsxYWVogAAAAAAAAAAAAAAAAAAAAAFhZWiAAAAAAAABvogAAOPUAAAOQWFlaIAAAAAAAAGKZAAC3hQAAGNpYWVogAAAAAAAAJKAAAA+EAAC2z2Rlc2MAAAAAAAAAFklFQyBodHRwOi8vd3d3LmllYy5jaAAAAAAAAAAAAAAAFklFQyBodHRwOi8vd3d3LmllYy5jaAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', '2016-04-30', '2016-05-26', 0, 1, 4, '2016-04-09 17:14:40', '2016-04-09 17:14:40'),
(10, 'Executive Requirements', '<p>Hi</p><h2 style="color: rgb(0, 0, 0);">Tag h2 for header section</h2><p><a href="http://www.googlw.com/maps">http://www.googlw.com/maps</a><a href="http://www.googlw.com/maps"></a></p><ol><li>Item one</li><li>Item two</li><li>Item three</li></ol><h2><br></h2>', '2016-04-12', '2016-04-12', 0, 2, 3, '2016-04-09 17:19:39', '2016-04-13 15:23:57'),
(11, 'How to reset password?', '<p>Hi</p><p>How to reset my password?</p><p><br></p>', '2016-04-12', '2016-04-12', 0, 3, 3, '2016-04-09 17:23:03', '2016-04-13 15:24:43'),
(12, 'Update Google Chrome', '<p><img src="https://lh3.googleusercontent.com/fKYxJWmqWKS5JTWJUHJSE6u4tKZ6JbFx7YGMbbH0cI72r3E2MhU0vPrE6uaflUm94Q=w64" style="width: 64px;"><br></p><p>To make sure you''re protected by the latest security updates, Google Chrome can automatically update when a new version of the browser is available on your computer, Android device, iPhone, or iPad. With these updates you might sometimes notice that your brow<br></p>', '2016-05-01', '2016-05-17', 0, 2, 4, '2016-04-09 17:26:09', '2016-04-09 17:26:09'),
(13, 'New Task', '<p>Test Description&nbsp;</p><ul><li>cookie</li><li>session</li></ul><h2>H2 Header</h2>', '2016-05-09', '2016-06-22', 0, 1, 3, '2016-05-23 04:10:43', '2016-05-23 04:14:14');

-- --------------------------------------------------------

--
-- Table structure for table `task_tags`
--

CREATE TABLE IF NOT EXISTS `task_tags` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `tag_id` int(10) unsigned DEFAULT NULL,
  `task_id` int(10) unsigned DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `updated_at` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  PRIMARY KEY (`id`),
  KEY `task_tags_tag_id_foreign` (`tag_id`),
  KEY `task_tags_task_id_foreign` (`task_id`)
) ENGINE=InnoDB  DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci AUTO_INCREMENT=27 ;

--
-- Dumping data for table `task_tags`
--

INSERT INTO `task_tags` (`id`, `tag_id`, `task_id`, `created_at`, `updated_at`) VALUES
(3, 3, 2, '2016-04-09 15:33:55', '2016-04-09 15:33:55'),
(4, 4, 2, '2016-04-09 15:33:55', '2016-04-09 15:33:55'),
(8, 2, 6, '2016-04-09 17:03:42', '2016-04-09 17:03:42'),
(9, 5, 7, '2016-04-09 17:05:19', '2016-04-09 17:05:19'),
(10, 4, 9, '2016-04-09 17:14:40', '2016-04-09 17:14:40'),
(15, 1, 12, '2016-04-09 17:26:09', '2016-04-09 17:26:09'),
(16, 3, 12, '2016-04-09 17:26:09', '2016-04-09 17:26:09'),
(17, 2, 3, '2016-04-13 15:22:17', '2016-04-13 15:22:17'),
(18, 1, 4, '2016-04-13 15:22:56', '2016-04-13 15:22:56'),
(20, 5, 10, '2016-04-13 15:23:57', '2016-04-13 15:23:57'),
(21, 1, 11, '2016-04-13 15:24:44', '2016-04-13 15:24:44'),
(22, 3, 11, '2016-04-13 15:24:44', '2016-04-13 15:24:44'),
(23, 6, 11, '2016-04-13 15:24:44', '2016-04-13 15:24:44'),
(26, 1, 13, '2016-05-23 04:14:15', '2016-05-23 04:14:15');

-- --------------------------------------------------------

--
-- Table structure for table `users`
--

CREATE TABLE IF NOT EXISTS `users` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `name` varchar(255) COLLATE utf8_unicode_ci NOT NULL,
  `email` varchar(255) COLLATE utf8_unicode_ci NOT NULL,
  `password` varchar(60) COLLATE utf8_unicode_ci NOT NULL,
  `avatar_url` varchar(50) COLLATE utf8_unicode_ci NOT NULL,
  `remember_token` varchar(100) COLLATE utf8_unicode_ci DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `updated_at` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `username` varchar(30) COLLATE utf8_unicode_ci DEFAULT NULL,
  `location` varchar(100) COLLATE utf8_unicode_ci DEFAULT NULL,
  `country` varchar(100) COLLATE utf8_unicode_ci DEFAULT NULL,
  `biography` varchar(255) COLLATE utf8_unicode_ci DEFAULT NULL,
  `occupation` varchar(255) COLLATE utf8_unicode_ci DEFAULT NULL,
  `website` varchar(255) COLLATE utf8_unicode_ci DEFAULT NULL,
  `image` varchar(255) COLLATE utf8_unicode_ci DEFAULT NULL,
  `status` int(11) NOT NULL DEFAULT '0',
  `birthday` date DEFAULT NULL,
  `gender` tinyint(4) DEFAULT NULL,
  `deleted_at` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `users_email_unique` (`email`)
) ENGINE=InnoDB  DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci AUTO_INCREMENT=6 ;

--
-- Dumping data for table `users`
--

INSERT INTO `users` (`id`, `name`, `email`, `password`, `avatar_url`, `remember_token`, `created_at`, `updated_at`, `username`, `location`, `country`, `biography`, `occupation`, `website`, `image`, `status`, `birthday`, `gender`, `deleted_at`) VALUES
(1, 'yepadmin', 'yep@gmail.com', '$2y$10$7ZQODCbkJj49JXSvKwiP5esCOIDDvqv50wu1xyWxHeZQVIlfrHknW', 'gKaaF4kCMN2ywCQ0EXJFavMsv.jpg', NULL, '2016-04-07 17:12:13', '2016-04-09 15:15:40', NULL, 'NY', 'US', NULL, NULL, NULL, NULL, 1, NULL, 0, NULL),
(2, 'Jack jastin', 'test@example.com', '$2y$10$rIyir5FetXXp6PiC7b7SwuU5vV0beNIYOwAwp0MeHjEr8GB.8.9qK', '1AL7w5xjgoTSjeLHod4BlCNXy.jpg', NULL, '2016-04-09 15:16:58', '2016-04-13 15:18:25', NULL, 'Landon', 'UK', NULL, NULL, NULL, NULL, 1, NULL, 0, NULL),
(3, 'Angle Shoper', 'angle@example.com', '$2y$10$ow6ClXpVnxfqxWVJuYXtxO/4AHff0HnzeuRIbTTXNK.fbyD9HSC1u', 'MrPtpB6lz1YZbxn2V6dnOK1RL.jpg', NULL, '2016-04-09 15:20:53', '2016-04-13 15:18:42', NULL, 'Pekan', 'China', NULL, NULL, NULL, NULL, 1, NULL, 1, NULL),
(4, 'Barak Kim', 'test@eample.com', '$2y$10$DMxW5ygvr3Ewk4OeQLVD4uhfPkpC1cjtNhrrDGSD6x9skXwxunXNu', '', NULL, '2016-05-23 04:23:14', '2016-05-23 04:23:14', NULL, NULL, NULL, NULL, NULL, NULL, NULL, 2016, NULL, 1, NULL),
(5, 'Nicole Kidman', 'test@example2.com', '$2y$10$qi9JXnHwLV3vhlIA8mV/uO.Hbk3EY118y5JEEKLd2zegcbevVlQ5u', 'V6zrlOiO0oaWRWfVKfqxmpwZg.jpg', NULL, '2016-05-23 04:23:14', '2016-05-23 04:27:31', NULL, NULL, NULL, NULL, NULL, NULL, NULL, 2016, NULL, 1, NULL);

--
-- Constraints for dumped tables
--

--
-- Constraints for table `comments`
--
ALTER TABLE `comments`
  ADD CONSTRAINT `comments_task_id_foreign` FOREIGN KEY (`task_id`) REFERENCES `tasks` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `comments_user_id_foreign` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE;

--
-- Constraints for table `galleries`
--
ALTER TABLE `galleries`
  ADD CONSTRAINT `galleries_task_id_foreign` FOREIGN KEY (`task_id`) REFERENCES `tasks` (`id`) ON DELETE CASCADE;

--
-- Constraints for table `permission_role`
--
ALTER TABLE `permission_role`
  ADD CONSTRAINT `permission_role_permission_id_foreign` FOREIGN KEY (`permission_id`) REFERENCES `permissions` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  ADD CONSTRAINT `permission_role_role_id_foreign` FOREIGN KEY (`role_id`) REFERENCES `roles` (`id`) ON DELETE CASCADE ON UPDATE CASCADE;

--
-- Constraints for table `role_user`
--
ALTER TABLE `role_user`
  ADD CONSTRAINT `role_user_role_id_foreign` FOREIGN KEY (`role_id`) REFERENCES `roles` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  ADD CONSTRAINT `role_user_user_id_foreign` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE ON UPDATE CASCADE;

--
-- Constraints for table `tasks`
--
ALTER TABLE `tasks`
  ADD CONSTRAINT `tasks_category_id_foreign` FOREIGN KEY (`category_id`) REFERENCES `categories` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `tasks_user_id_foreign` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE;

--
-- Constraints for table `task_tags`
--
ALTER TABLE `task_tags`
  ADD CONSTRAINT `task_tags_tag_id_foreign` FOREIGN KEY (`tag_id`) REFERENCES `tags` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `task_tags_task_id_foreign` FOREIGN KEY (`task_id`) REFERENCES `tasks` (`id`) ON DELETE CASCADE;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;

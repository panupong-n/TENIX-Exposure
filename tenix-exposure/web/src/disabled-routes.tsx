// Template pages that TENIX Exposure does not use yet. They are switched off, not deleted:
// nothing imports this file, so none of these pages is routed, linked or bundled.
// To turn one back on, move its <Route> into App.tsx and its sidebar entry from
// components/layout/app-layout/sidebar/disabled-data.tsx into data.tsx.
import CalendarPage from "@/pages/main/calendar";
import EcommercePage from "@/pages/main/dashboard/ecommerce";
import FormElementsPage from "@/pages/main/forms/form-elements";
import { BlankPage } from "@/pages/main/pages";
import ProfilePage from "@/pages/main/profile";
import BasicTablesPage from "@/pages/main/tables/basic-tables";
import { SignUpPage } from "@/pages/others/auth";
import BarChartPage from "@/pages/others/charts/bar-chart";
import LineChartPage from "@/pages/others/charts/line-chart";
import Alerts from "@/pages/others/ui-elements/alerts";
import Avatars from "@/pages/others/ui-elements/avatars";
import Badges from "@/pages/others/ui-elements/badges";
import Buttons from "@/pages/others/ui-elements/buttons";
import Images from "@/pages/others/ui-elements/images";
import Videos from "@/pages/others/ui-elements/videos";
import "flatpickr/dist/flatpickr.css";
import { Route } from "react-router";

/** Inside the <Route element={<AppLayout />}> group. */
export const disabledAppRoutes = (
  <>
    <Route path="/ecommerce" element={<EcommercePage />} />
    <Route path="/profile" element={<ProfilePage />} />
    <Route path="/calendar" element={<CalendarPage />} />
    <Route path="/blank" element={<BlankPage />} />
    <Route path="/form-elements" element={<FormElementsPage />} />
    <Route path="/basic-tables" element={<BasicTablesPage />} />
    <Route path="/alerts" element={<Alerts />} />
    <Route path="/avatars" element={<Avatars />} />
    <Route path="/badge" element={<Badges />} />
    <Route path="/buttons" element={<Buttons />} />
    <Route path="/images" element={<Images />} />
    <Route path="/videos" element={<Videos />} />
    <Route path="/line-chart" element={<LineChartPage />} />
    <Route path="/bar-chart" element={<BarChartPage />} />
  </>
);

/** Inside the <Route element={<AuthLayout />}> group. Replaced by invite-only sign-up. */
export const disabledAuthRoutes = <Route path="/signup" element={<SignUpPage />} />;
